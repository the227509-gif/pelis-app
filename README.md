# PELIS — aplicación web progresiva independiente

Proyecto propio, sin dependencia de Lovable. Incluye frontend responsive/PWA, servidor Node.js, Socket.IO, SQLite, autenticación local, perfiles, amistades, salas, chat, reproducción sincronizada básica, integración OAuth de Google Drive y señalización WebRTC mesh.

## Ejecutar localmente
Requiere Node.js 20+.
1. Copia `.env.example` a `.env`.
2. Genera valores aleatorios largos para `SESSION_SECRET` y `TOKEN_ENCRYPTION_KEY`.
3. `npm install`
4. `npm start`
5. Abre `http://localhost:3000`.

## Funciones y límites importantes
- Registro/inicio de sesión con usuario, correo y contraseña. Contraseñas con bcrypt.
- Perfiles y solicitudes de amistad.
- Sesiones persistidas en SQLite.
- Restablecimiento de contraseña por correo si SMTP está configurado.
- OAuth de Drive y selector de vídeos. Cada participante necesita iniciar sesión en Pelis; el anfitrión comparte el vídeo a través del proxy de Drive autorizado a los miembros de la sala.
- Sala y estado compartido play/pause/seek por Socket.IO.
- Audio grupal P2P WebRTC con STUN básico. Para grupos grandes o redes restrictivas se recomienda un SFU/TURN administrado; no se garantiza conexión en todas las redes con STUN solamente.
- El selector de calidad es una preferencia visual/local. Drive no ofrece por sí mismo una escalera ABR de 360p–1080p para cada usuario. Para calidad independiente real se necesita un pipeline de transcodificación HLS/DASH y almacenamiento/entrega CDN.
- Archivos locales del teléfono/PC son locales y no se comparten. Para ver todos el mismo archivo, utiliza el flujo de Drive implementado. Compatibilidad depende del códec/formato que admita el navegador.
- No se promete latencia cero. La reproducción sincroniza el estado y corrige desviaciones; el buffering y la red de cada participante pueden producir diferencias.
- Chat de texto y emojis está implementado; stickers GIF requieren integrar un proveedor o almacenamiento de medios con moderación.
- No incluye publicidad ni marcas de agua.

## Despliegue en Railway
1. Crea un proyecto en Railway e importa este repositorio/ZIP en un repositorio Git.
2. Añade un volumen persistente montado en `/data` y establece `DATA_DIR=/data`. La base de datos de usuarios y las sesiones se guardan dentro de ese volumen.
3. Variables necesarias: `SESSION_SECRET`, `TOKEN_ENCRYPTION_KEY`, `BASE_URL`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`.
4. Para recuperar contraseña: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`.
5. Configura en Google Cloud Console el OAuth consent screen y un OAuth Client tipo Web. Añade el callback exacto `https://TU-DOMINIO/auth/google/callback` a Authorized redirect URIs. Publica/verifica el consentimiento OAuth según las políticas de Google.
6. Asigna dominio HTTPS y configura `BASE_URL` con ese dominio.
7. Health check: `/health`.

## Antes de abrir al público
Haz pruebas de carga y seguridad, políticas de privacidad y retención, verificación de correo, límites antiabuso por usuario/IP, TURN/SFU para audio confiable, CDN/transcodificación para calidades independientes, copias de seguridad y monitoreo. No se ha desplegado ni validado en una cuenta real de hosting desde este paquete. Para alojar la aplicación se requiere una cuenta Railway autorizada y sus variables/credenciales.
