
# emuladorMEMU

Repositorio de herramientas y scripts para capturar el Bearer token de LaLiga Fantasy usando MEMU, root, Firefox y Frida.

## ¿Qué contiene este repositorio?
- Scripts automatizados para preparar el entorno (`descargar_herramientas.py`)
- Scripts de captura (`captura_bearer.py`, `frida_combined_unroot_capture.js`)
- Utilidades y recursos para root, bypass y análisis
- Instrucciones detalladas paso a paso (ver más abajo)

## Guía rápida

1. Instala MEMU y configura el emulador (root, Firefox, desinstala Chrome, activa depuración USB)
2. Descarga este repositorio y ejecuta `python descargar_herramientas.py`
3. Instala frida-server en el emulador con ADB
4. Ejecuta `python captura_bearer.py` y haz login en la app
5. Copia el token de `frida_capture.log` o `.env.local`

Consulta el README completo para instrucciones detalladas y solución de problemas.

---

# Herramientas para Emulación y Análisis

En esta carpeta gestionamos todo lo necesario para instrumentar, rootear y analizar apps Android desde el emulador (MEmu, LDPlayer, etc).

---

## Progreso y pasos realizados

### ✅ Preparación del entorno

1. **Descarga automática de herramientas**  
   - Ejecuta `descargar_herramientas.py` para obtener:
     - platform-tools (ADB)
     - frida-server (y descomprimirlo)
     - APKs y ZIPs útiles (RootCloak, etc.)

2. **Arranque y conexión con el emulador**
   - Abre MEmu y asegúrate de que el root está activado en los ajustes de MEmu.
   - Comprueba la conexión ADB:
     ```
     adb devices
     ```
   - Debes ver tu emulador listado.

3. **Instalación y arranque de frida-server**
   - Copia y da permisos al binario:
     ```
     adb push frida/frida-server /data/local/tmp/
     adb shell "chmod 755 /data/local/tmp/frida-server"
     ```
   - Lanza frida-server en el emulador:
     ```
     adb shell "su -c '/data/local/tmp/frida-server &'"
     ```
   - Deja esta terminal abierta y funcionando.

4. **Instalación de la app objetivo y RootCloak**
   - Instala la app de LaLiga Fantasy:
     ```
     adb install <LaLigaFantasy.apk>
     ```
   - Instala RootCloak (aunque en MEmu no funcionará sin Xposed/LSPosed, se deja por si cambias de emulador):
     ```
     adb install rootcloak/RootCloak-release.apk
     ```

---

### ✅ Bypass de root detection con Frida

5. **Lanzar la app con el script de unroot**
   - En una segunda terminal:
     ```
     frida -U -f com.lfp.laligafantasy -l unroot.js
     ```
   - Cuando aparezca el prompt de Frida, escribe:
     ```
     %resume
     ```
   - La app debería arrancar sin detectar root.

---

### ✅ Captura de tráfico HTTP y Bearer

6. **Script Frida actualizado (`frida_combined_unroot_capture.js`):**
   - El script:
     - Hookea y registra todas las peticiones HTTP justo antes de enviarse (OkHttp, HttpURLConnection, Volley, Apache HttpClient, WebView).
     - Guarda el log en el dispositivo y exporta el Bearer token automáticamente.
     - El token se guarda en el log y en formato env como:
       ```
       NEXT_PUBLIC_LALIGA_BEARER=eyJhbGciOi...
       ```
   - El log generado es útil para replicar peticiones en Postman o código.

7. **Script Python (`captura_bearer.py`):**
   - Lanza la app, carga el script Frida y extrae el log/Bearer.
   - Busca el token en el log y lo guarda en `.env.local` como `NEXT_PUBLIC_LALIGA_BEARER=...`.

8. **Reinicia el servidor Next.js** para que la variable de entorno se aplique y el botón de Google Sign-In esté disponible en la web.

---

## ⏳ Estado actual

- El entorno está listo y funcional.
- El bypass de root detection funciona.
- El script Frida captura correctamente las peticiones HTTP y el Bearer.
- El token Bearer se guarda automáticamente en `.env.local` para la web.
- El análisis de buffers binarios se ha descartado por no aportar información útil.
- El siguiente paso será continuar el análisis de las peticiones capturadas y, si es necesario, reforzar los hooks o analizar el APK para detectar otras formas de tráfico.

---

**Continuar mañana**