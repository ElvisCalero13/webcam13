# Companion Android para control web (beta)

Este proyecto añade el único permiso que falta para los controles: un servicio de accesibilidad de alcance limitado que acepta comandos JSON por un socket enlazado solo a `127.0.0.1` en el Android. El servidor de laptop crea un `adb forward` únicamente por USB y no usa `adb shell input` (Android 16 lo rechaza con `INJECT_EVENTS`).

El companion no solicita leer contenido de ventanas ni captura pantalla. Solo implementa gestos de toque/arrastre y acciones globales Atrás/Inicio, cuando el usuario habilita expresamente el servicio desde Ajustes de accesibilidad.

## Preparar SDK y compilar

El equipo ya tiene JDK 25. Falta Android SDK (no se encontró en las rutas estándar). Instala Android Studio desde el sitio oficial de Android o sus Command-line Tools. En el asistente acepta personalmente los términos de licencia Android SDK e instala:

- Android SDK Platform 36
- Android SDK Build-Tools 36.0.0
- Android SDK Platform-Tools

Después ejecuta `Build-Bridge.cmd`. La salida será `app\build\outputs\apk\debug\app-debug.apk`.

La aceptación de la licencia debe hacerla el usuario en el asistente de instalación; el agente no la aceptará en su nombre.

## Activar el companion

1. Instala el APK generado en el teléfono: `adb install -r app-debug.apk`.
2. Abre **Control local HDCameraPro** en el Android.
3. Pulsa **Abrir ajustes de accesibilidad**, habilita **Control local HDCameraPro** y confirma el aviso de Android.
4. Vuelve al companion; debe indicar que el servicio está habilitado.
5. Recarga la web beta. El estado debe mostrar **control listo**; entonces Atrás/Inicio y toques/arrastres usan AccessibilityService.

El listener del companion no expone un puerto a la LAN; solo escucha loopback del Android y la laptop crea el túnel ADB USB. Deshabilita el servicio desde Ajustes cuando dejes de usar la beta.
