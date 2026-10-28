# HDCameraPro: beta local

Cliente web y backend Node.js para conectarse directamente a una cámara H10 desde una laptop en la misma red. La conexión directa no requiere mantener el teléfono conectado ni integra el SDK propietario de la cámara.

## Ejecutar la beta de cámara

Consulta [backend-local/README.md](backend-local/README.md) para requisitos y pasos completos. Resumen:

1. Instala Node.js y FFmpeg en Windows.
2. Crea `backend-local/.env` copiando `backend-local/.env.example` y añade la contraseña local de la cámara.
3. Ejecuta `backend-local\Iniciar-Beta.cmd`.
4. Abre `http://127.0.0.1:8787/`, busca la cámara y conecta.

La laptop y la cámara deben estar en la misma red local. No subas `backend-local/.env` a GitHub; el `.gitignore` lo excluye. El archivo `.env.example` no contiene credenciales reales y sí debe incluirse en el repositorio.

## Contenido del repositorio

- `backend-local/`: web, backend Node.js, cliente LAN, plantilla `.env.example` y documentación.
- `backend-local/android-control-bridge/`: fuente opcional para espejo y controles táctiles del teléfono por USB. No se requiere para el stream directo de cámara.

## Publicar en GitHub

El repositorio excluye credenciales `.env`, capturas PCAP/H.264, APK extraídos y salidas de compilación. Usa `backend-local/.env.example` como plantilla y crea `backend-local/.env` localmente en cada equipo. No añadas capturas que puedan revelar identificadores o tráfico privado de la cámara.
