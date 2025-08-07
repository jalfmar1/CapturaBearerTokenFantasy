

# CapturaBearerTokenFantasy (emuladorMEMU)

Repositorio de herramientas y scripts para capturar el Bearer token de LaLiga Fantasy usando MEMU, root, Firefox y Frida.

## ¿Qué contiene este repositorio?
- Script automatizado para preparar el entorno (`descargar_herramientas.py`)
- Script de captura (`captura_bearer.py` y `frida_combined_unroot_capture.js`)
- Utilidades ADB y Frida
- Instrucciones detalladas paso a paso

## Guía rápida

1. Instala MEMU y configura el emulador:
   - Activa el modo root en los ajustes de MEMU.
   - Instala la APK de LaLiga Fantasy (arrástrala al emulador).
   - Instala Firefox desde Google Play Store dentro del emulador.
   - Desinstala Chrome (opcional, pero recomendado para forzar el login con Firefox).
   - Activa la depuración USB (Developer Options > USB Debugging).
2. Descarga este repositorio y ejecuta `python descargar_herramientas.py` para obtener ADB y frida-server.
3. Instala y lanza frida-server en el emulador:
   ```
   adb push frida/frida-server /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/frida-server"
   adb shell "/data/local/tmp/frida-server &"
   ```
4. Ejecuta el script de captura:
   ```
   python captura_bearer.py
   ```
   - El script abrirá la app en el emulador. Haz login con Google usando Firefox.
   - El token se capturará automáticamente y aparecerá en `frida_capture.log` y `.env.local`.
5. Copia el valor de `BEARER_TOKEN=...` y pégalo en la app web.

---

## Notas y buenas prácticas
- No subas nunca tu `frida_capture.log` ni `.env.local` a ningún repositorio.
- El token Bearer es personal y sensible, no lo compartas.
- Si el token deja de funcionar, repite el proceso de captura.

---