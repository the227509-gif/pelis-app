import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import http from 'http';
import { Server } from 'socket.io';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import connectSqlite3 from 'connect-sqlite3';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import crypto from 'node:crypto';
import fs from 'node:fs';
import nodemailer from 'nodemailer';
import { google } from 'googleapis';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = process.env.DATA_DIR || __dirname;
fs.mkdirSync(dataDir, { recursive: true });
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true, credentials: true } });
const db = new Database(process.env.DB_PATH || path.join(dataDir, 'pelis.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE COLLATE NOCASE NOT NULL,
 email TEXT UNIQUE COLLATE NOCASE NOT NULL, password_hash TEXT NOT NULL,
 bio TEXT DEFAULT '', photo TEXT DEFAULT '', joined_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS google_tokens (
 user_id INTEGER PRIMARY KEY, token_blob TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS password_resets (
 user_id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS friendships (
 id INTEGER PRIMARY KEY AUTOINCREMENT, from_id INTEGER NOT NULL, to_id INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', UNIQUE(from_id,to_id)
);
`);
app.set('trust proxy', 1);
app.use(helmet({contentSecurityPolicy:false,crossOriginEmbedderPolicy:false}));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '3mb' }));
const SQLiteStore = connectSqlite3(session);
const sessionMiddleware = session({
 store: new SQLiteStore({ db: 'sessions.sqlite', dir: dataDir, concurrentDB: true }),
 secret: process.env.SESSION_SECRET || 'CHANGE-ME-before-production',
 resave: false, saveUninitialized: false,
 cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7*24*60*60*1000 }
});
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, 'public')));
const authLimiter=rateLimit({windowMs:15*60*1000,limit:20,standardHeaders:true,legacyHeaders:false});
app.use(['/api/login','/api/register','/api/password/forgot','/api/password/reset'],authLimiter);
const getUser = req => req.session.userId ? db.prepare('SELECT id,username,email,bio,photo,joined_at FROM users WHERE id=?').get(req.session.userId) : null;
const auth = (req,res,next) => { const u=getUser(req); if(!u) return res.status(401).json({error:'Inicia sesión'}); req.user=u; next(); };


const encryptionKey = () => {
 const raw=process.env.TOKEN_ENCRYPTION_KEY;
 if(!raw || raw==='CHANGE-ME-before-production') return null;
 return crypto.createHash('sha256').update(raw).digest();
};
function encryptJson(obj) {
 const key=encryptionKey(); if(!key) throw new Error('Configura TOKEN_ENCRYPTION_KEY');
 const iv=crypto.randomBytes(12), cipher=crypto.createCipheriv('aes-256-gcm',key,iv);
 const data=Buffer.concat([cipher.update(JSON.stringify(obj),'utf8'),cipher.final()]);
 return Buffer.concat([iv,cipher.getAuthTag(),data]).toString('base64');
}
function decryptJson(blob) {
 const key=encryptionKey(); if(!key) throw new Error('Configura TOKEN_ENCRYPTION_KEY');
 const b=Buffer.from(blob,'base64'),iv=b.subarray(0,12),tag=b.subarray(12,28),data=b.subarray(28);
 const decipher=crypto.createDecipheriv('aes-256-gcm',key,iv);decipher.setAuthTag(tag);
 return JSON.parse(Buffer.concat([decipher.update(data),decipher.final()]).toString('utf8'));
}
function oauthClient() {
 if(!process.env.GOOGLE_CLIENT_ID||!process.env.GOOGLE_CLIENT_SECRET) throw new Error('Google OAuth no está configurado.');
 return new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID,process.env.GOOGLE_CLIENT_SECRET,process.env.GOOGLE_REDIRECT_URI||`${process.env.BASE_URL}/auth/google/callback`);
}
function driveFor(userId) {
 const row=db.prepare('SELECT token_blob FROM google_tokens WHERE user_id=?').get(userId);
 if(!row) throw new Error('Conecta primero tu cuenta de Google Drive.');
 const auth=oauthClient();auth.setCredentials(decryptJson(row.token_blob));
 auth.on('tokens',tokens=>{
  const current=db.prepare('SELECT token_blob FROM google_tokens WHERE user_id=?').get(userId);
  const old=current?decryptJson(current.token_blob):{};
  db.prepare('INSERT INTO google_tokens(user_id,token_blob,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET token_blob=excluded.token_blob,updated_at=excluded.updated_at')
   .run(userId,encryptJson({...old,...tokens}),new Date().toISOString());
 });
 return google.drive({version:'v3',auth});
}
app.post('/api/register', async (req,res) => {
 const {username,email,password}=req.body||{};
 if(!/^[\p{L}\p{N}_.-]{3,24}$/u.test(username||'')) return res.status(400).json({error:'El usuario debe tener 3–24 caracteres.'});
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email||'')) return res.status(400).json({error:'Correo no válido.'});
 if(typeof password!=='string'||password.length<8) return res.status(400).json({error:'La contraseña debe tener al menos 8 caracteres.'});
 try {
  const info=db.prepare('INSERT INTO users(username,email,password_hash,joined_at) VALUES(?,?,?,?)')
   .run(username,email.toLowerCase(),await bcrypt.hash(password,12),new Date().toISOString());
  req.session.userId=info.lastInsertRowid;
  res.json({user:getUser(req)});
 } catch { res.status(409).json({error:'Ese usuario o correo ya está registrado.'}); }
});
app.post('/api/login', async (req,res) => {
 const {username,password}=req.body||{};
 const u=db.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE').get(username||'');
 if(!u || !(await bcrypt.compare(password||'',u.password_hash))) return res.status(401).json({error:'Usuario o contraseña incorrectos.'});
 req.session.userId=u.id; res.json({user:getUser(req)});
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/health',(req,res)=>res.json({ok:true,app:'Pelis'}));
app.get('/api/me',(req,res)=>res.json({user:getUser(req)}));
app.patch('/api/profile',auth,(req,res)=>{
 const {username,bio,photo}=req.body||{};
 if(username!==undefined && !/^[\p{L}\p{N}_.-]{3,24}$/u.test(username)) return res.status(400).json({error:'Nombre de usuario no válido.'});
 try {
  db.prepare('UPDATE users SET username=COALESCE(?,username),bio=COALESCE(?,bio),photo=COALESCE(?,photo) WHERE id=?')
   .run(username??null,typeof bio==='string'?bio.slice(0,300):null,typeof photo==='string'?photo.slice(0,1500000):null,req.user.id);
  res.json({user:getUser(req)});
 } catch { res.status(409).json({error:'Ese nombre de usuario ya existe.'}); }
});
app.get('/api/users/:username',auth,(req,res)=>{
 const u=db.prepare('SELECT username,bio,photo,joined_at FROM users WHERE username=? COLLATE NOCASE').get(req.params.username);
 if(!u) return res.status(404).json({error:'Usuario no encontrado'}); res.json({user:u});
});
app.post('/api/friends',auth,(req,res)=>{
 const target=db.prepare('SELECT id FROM users WHERE email=? COLLATE NOCASE').get(req.body.email||'');
 if(!target) return res.status(404).json({error:'No encontramos una cuenta con ese correo.'});
 if(target.id===req.user.id) return res.status(400).json({error:'No puedes agregarte a ti mismo.'});
 try { db.prepare("INSERT INTO friendships(from_id,to_id,status) VALUES(?,?,'pending')").run(req.user.id,target.id); res.json({ok:true}); }
 catch { res.status(409).json({error:'La solicitud ya existe.'}); }
});
app.get('/api/friends',auth,(req,res)=>{
 const rows=db.prepare(`SELECT u.username,u.email,f.status FROM friendships f JOIN users u ON
 (u.id=CASE WHEN f.from_id=? THEN f.to_id ELSE f.from_id END)
 WHERE f.from_id=? OR f.to_id=?`).all(req.user.id,req.user.id,req.user.id);
 res.json({friends:rows});
});

app.get('/auth/google',auth,(req,res)=>{
 try {
  const client=oauthClient();
  const state=crypto.randomBytes(24).toString('hex');req.session.oauthState=state;
  const url=client.generateAuthUrl({access_type:'offline',prompt:'consent',include_granted_scopes:true,
   scope:['https://www.googleapis.com/auth/drive.readonly'],state});
  res.redirect(url);
 } catch(e){res.status(503).send(e.message)}
});
app.get('/auth/google/callback',auth,async(req,res)=>{
 try {
  if(!req.query.state||req.query.state!==req.session.oauthState) return res.status(400).send('Estado OAuth inválido.');
  delete req.session.oauthState;
  const client=oauthClient();const {tokens}=await client.getToken(String(req.query.code||''));client.setCredentials(tokens);
  db.prepare('INSERT INTO google_tokens(user_id,token_blob,updated_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET token_blob=excluded.token_blob,updated_at=excluded.updated_at')
   .run(req.user.id,encryptJson(tokens),new Date().toISOString());
  res.redirect('/?drive=connected');
 }catch(e){res.status(400).send('No se pudo conectar Google Drive: '+e.message)}
});
app.get('/api/drive/status',auth,(req,res)=>res.json({connected:!!db.prepare('SELECT 1 FROM google_tokens WHERE user_id=?').get(req.user.id)}));
app.get('/api/drive/files',auth,async(req,res)=>{
 try {
  const d=driveFor(req.user.id);
  const out=await d.files.list({q:"trashed=false and mimeType contains 'video/'",pageSize:100,orderBy:'name',fields:'files(id,name,mimeType,size,thumbnailLink,webViewLink)'});
  res.json({files:out.data.files||[]});
 }catch(e){res.status(400).json({error:e.message})}
});
app.get('/api/drive/stream/:fileId',auth,async(req,res)=>{
 try {
  const roomId=String(req.query.room||'');
  if(!roomMembers.get(roomId)?.has(req.user.id)) return res.status(403).end('No perteneces a esta sala.');
  const ownerId=Number(req.query.owner||req.user.id);
  if(!roomMembers.get(roomId)?.has(ownerId)) return res.status(403).end('El propietario del archivo no pertenece a esta sala.');
  const d=driveFor(ownerId);
  const meta=await d.files.get({fileId:req.params.fileId,fields:'id,name,mimeType,size'});
  if(!String(meta.data.mimeType||'').startsWith('video/')) return res.status(415).end('Archivo no compatible.');
  const headers={};
  if(req.headers.range) headers.Range=req.headers.range;
  const result=await d.files.get({fileId:req.params.fileId,alt:'media'},{responseType:'stream',headers});
  res.status(result.status||200);
  res.setHeader('Content-Type',meta.data.mimeType);
  if(meta.data.size)res.setHeader('Accept-Ranges','bytes');
  for(const h of ['content-range','content-length','accept-ranges'])if(result.headers[h])res.setHeader(h,result.headers[h]);
  result.data.on('error',()=>res.destroy());result.data.pipe(res);
 }catch(e){if(!res.headersSent)res.status(400).send('No se pudo transmitir el archivo de Drive: '+e.message);else res.destroy()}
});
app.post('/api/password/forgot',async(req,res)=>{
 const email=String(req.body?.email||'').toLowerCase();
 const u=db.prepare('SELECT id,email FROM users WHERE email=?').get(email);
 // Always return the same response to avoid revealing whether an account exists.
 if(u&&process.env.SMTP_HOST&&process.env.SMTP_FROM){
  try{
   const token=crypto.randomBytes(32).toString('hex'),hash=crypto.createHash('sha256').update(token).digest('hex');
   db.prepare('INSERT INTO password_resets(user_id,token_hash,expires_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,expires_at=excluded.expires_at')
    .run(u.id,hash,Date.now()+3600000);
   const transporter=nodemailer.createTransport({host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),secure:Number(process.env.SMTP_PORT)===465,auth:process.env.SMTP_USER?{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}:undefined});
   const link=`${process.env.BASE_URL}/?reset=${token}`;
   await transporter.sendMail({from:process.env.SMTP_FROM,to:u.email,subject:'Restablecer contraseña de Pelis',text:`Para cambiar tu contraseña abre este enlace (válido por una hora): ${link}`});
  }catch(e){console.error('SMTP reset:',e.message)}
 }
 res.json({message:'Si el correo está registrado y el servicio de correo está configurado, recibirás instrucciones.'});
});
app.post('/api/password/reset',async(req,res)=>{
 const token=String(req.body?.token||''),password=String(req.body?.password||'');
 if(password.length<8)return res.status(400).json({error:'La contraseña debe tener al menos 8 caracteres.'});
 const hash=crypto.createHash('sha256').update(token).digest('hex');
 const row=db.prepare('SELECT * FROM password_resets WHERE token_hash=? AND expires_at>?').get(hash,Date.now());
 if(!row)return res.status(400).json({error:'El enlace no es válido o ha vencido.'});
 db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await bcrypt.hash(password,12),row.user_id);
 db.prepare('DELETE FROM password_resets WHERE user_id=?').run(row.user_id);res.json({ok:true});
});

const rooms = new Map();
const roomMembers = new Map();
io.engine.use(sessionMiddleware);
const roomState = id => { if(!rooms.has(id)) rooms.set(id,{playing:false,position:0,updatedAt:Date.now(),source:null}); return rooms.get(id); };
io.on('connection',socket=>{
 socket.on('room:join',({roomId})=>{
  if(!/^[a-zA-Z0-9_-]{4,48}$/.test(roomId||'')) return;
  const sess=socket.request.session;
  const u=sess?.userId?db.prepare('SELECT id,username FROM users WHERE id=?').get(sess.userId):null;
  if(!u)return socket.disconnect(true);
  socket.join(roomId); socket.data.roomId=roomId; socket.data.userId=u.id; socket.data.username=u.username;
  if(!roomMembers.has(roomId))roomMembers.set(roomId,new Set());roomMembers.get(roomId).add(u.id);
  socket.to(roomId).emit('room:user',{username:socket.data.username,action:'joined',socketId:socket.id});
  socket.emit('playback:state',roomState(roomId));
  socket.emit('room:members',[...io.sockets.adapter.rooms.get(roomId)||[]].filter(id=>id!==socket.id).map(id=>({socketId:id,username:io.sockets.sockets.get(id)?.data.username||'Invitado'})));
 });
 socket.on('room:voice:join',()=>{const id=socket.data.roomId;if(id)socket.emit('room:members',[...io.sockets.adapter.rooms.get(id)||[]].filter(pid=>pid!==socket.id).map(pid=>({socketId:pid,username:io.sockets.sockets.get(pid)?.data.username||'Invitado'})));});
 socket.on('playback:command',cmd=>{
  const id=socket.data.roomId; if(!id) return;
  const s=roomState(id);
  if(cmd.type==='play'||cmd.type==='pause'){s.playing=cmd.type==='play';s.position=Math.max(0,Number(cmd.position)||0);s.updatedAt=Date.now();}
  if(cmd.type==='seek'){s.position=Math.max(0,Number(cmd.position)||0);s.updatedAt=Date.now();}
  if(cmd.type==='source'){s.source=String(cmd.source||'').slice(0,2048);s.position=0;s.playing=false;s.updatedAt=Date.now();}
  io.to(id).emit('playback:state',s);
 });
 socket.on('chat:message',m=>{
  const id=socket.data.roomId;if(!id)return;
  const text=String(m?.text||'').slice(0,1000);if(!text.trim())return;
  io.to(id).emit('chat:message',{username:socket.data.username,text,at:Date.now()});
 });
 socket.on('voice:relay',({to,payload})=>{const target=io.sockets.sockets.get(to);if(to&&payload&&socket.data.roomId&&target?.data.roomId===socket.data.roomId)target.emit('voice:signal',{from:socket.id,payload});});
 socket.on('disconnect',()=>{if(socket.data.roomId){socket.to(socket.data.roomId).emit('room:user',{username:socket.data.username,action:'left',socketId:socket.id});roomMembers.get(socket.data.roomId)?.delete(socket.data.userId);}});
});
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
const port=process.env.PORT||3000;
server.listen(port,'0.0.0.0',()=>console.log(`PELIS escuchando en ${port}`));
