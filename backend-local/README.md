# Beta local de HDCameraPro

Backend Node.js y página web para ver la cámara directamente desde una laptop en la misma red local. El flujo directo no necesita que el teléfono permanezca conectado ni integra el SDK propietario de la cámara. La beta también conserva, como función opcional, el espejo y control de Android por USB.

## Requisitos para ver la cámara directamente

- Windows 10/11.
- Node.js instalado y disponible como `node` en PowerShell o CMD.
- FFmpeg instalado y disponible como `ffmpeg` en `PATH`; se usa para convertir el video H.264 recibido a una salida que reproduce el navegador.
- Laptop y cámara conectadas a la misma red local, con comunicación entre dispositivos permitida.
- Credenciales locales de la cámara configuradas en `.env` (ver abajo).

No se requiere Android Studio, ADB ni conectar el teléfono para el flujo directo de cámara.

## Primera configuración

1. En GitHub, descarga o clona el repositorio completo; conserva la carpeta `backend-local` y su subcarpeta `src`.
2. En PowerShell, desde la carpeta del repositorio, crea la configuración privada:

   ```powershell
   Copy-Item backend-local/.env.example backend-local/.env
   notepad backend-local/.env
   ```

3. En `backend-local/.env`, completa `HDCAMERA_PASSWORD`. El usuario predeterminado es `admin`; modifica `HDCAMERA_ACCOUNT` si tu cámara usa otro. No subas ni compartas el archivo `.env`.
4. Instala FFmpeg y verifica que `node --version` y `ffmpeg -version` funcionen en una terminal nueva.

Ejemplo de configuración:

```dotenv
HDCAMERA_ACCOUNT=admin
HDCAMERA_PASSWORD="escribe aquí la contraseña local"
```

Si la contraseña contiene `#`, espacios al inicio/final o comillas, mantenla entre comillas dobles y escapa las comillas dobles internas. El archivo `.env` está excluido de Git; `.env.example` es una plantilla sin credenciales reales.

## Iniciar y usar

1. Ejecuta `backend-local\Iniciar-Beta.cmd` desde el Explorador de archivos o la terminal. Deja abierta la consola.
2. Abre `http://127.0.0.1:8787/` en el navegador de esa misma laptop.
3. Pulsa **Buscar cámara en LAN** y luego **Conectar y ver video** en el dispositivo encontrado.

El servidor escucha solo en `127.0.0.1`; la página no queda expuesta a otros equipos de la red. Si cambias la contraseña o el `.env`, reinicia el backend para cargar los cambios. Si el puerto 8787 está ocupado, puedes iniciar Node con la variable `PORT` configurada.

## Funciones opcionales de Android por USB

El espejo de pantalla y los controles táctiles del teléfono son funciones separadas del video directo de la cámara. Para usarlos se requiere Android Platform Tools (`adb.exe`), un Android conectado por USB con depuración USB autorizada y el companion de `android-control-bridge/` instalado. Para toques interactivos, también hay que habilitar manualmente **Control local HDCameraPro** en Ajustes → Accesibilidad.

El iniciador busca ADB en `C:\platform-tools\adb.exe` y luego en `PATH`. Si está en otra ubicación, configura `ADB_PATH`. La compilación del companion requiere Android Studio/SDK, JDK y las versiones indicadas en [android-control-bridge/README.md](android-control-bridge/README.md). Nada de esto es necesario para conectarse directamente a la cámara.

## Seguridad y alcance

- No guardes credenciales reales en GitHub. El repositorio incluye `.env.example`; cada instalación debe crear su propio `.env`.
- La contraseña se usa desde el backend para autenticar con la cámara y no se devuelve a la página web. El protocolo observado usa ofuscación reversible, no cifrado robusto.
- La cámara debe ser accesible desde la red local de la laptop. Las redes de invitados o el aislamiento Wi-Fi pueden impedir la conexión.
- El video directo se mantuvo funcionando durante una prueba reportada de aproximadamente dos horas. La beta aún está en desarrollo; no todas las funciones de la app original (por ejemplo, cambiar calidad) están confirmadas.
