import frida
import subprocess
import os
import re
import time
import sys

FRIDA_SCRIPT = "frida_combined_unroot_capture.js"
PACKAGE = "com.lfp.laligafantasy"
LOG_PATH_EMU = "/data/data/com.lfp.laligafantasy/frida_capture.log"
LOG_PATH_LOCAL = "frida_capture.log"
ENV_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env.local"))

def adb_pull():
    print("Extrayendo el log del emulador...")
    result = subprocess.run([
        "adb", "pull", LOG_PATH_EMU, LOG_PATH_LOCAL
    ], capture_output=True, text=True)
    if result.returncode == 0:
        print("Log extraído correctamente.")
        return True
    else:
        print("Error extrayendo el log:", result.stderr)
        return False

def extrae_bearer_y_guarda_env():
    print("Buscando el token Bearer en el log...")
    if not os.path.exists(LOG_PATH_LOCAL):
        print("No se encontró el log local.")
        return False
    with open(LOG_PATH_LOCAL, encoding="utf-8") as f:
        contenido = f.read()
    m = re.search(r"(?:LALIGA_BEARER|NEXT_PUBLIC_LALIGA_BEARER|BEARER_TOKEN)=([A-Za-z0-9\-\._~\+\/]+=*)", contenido)
    if m:
        bearer = m.group(1)
        print(f"Token capturado: {bearer}")
        return True
    else:
        print("No se encontró ningún token Bearer en el log.")
        return False

def espera_log_y_bearer(timeout=600):
    print("Capturando logs y Bearer tokens continuamente (CTRL+C para salir)...")
    start = time.time()
    while time.time() - start < timeout:
        if adb_pull():
            extrae_bearer_y_guarda_env()
        time.sleep(2)
    print("Fin de la captura continua.")
    return False

def main():
    print("Lanzando Frida y la app...")
    device = frida.get_usb_device()
    pid = device.spawn([PACKAGE])
    session = device.attach(pid)
    with open(FRIDA_SCRIPT, "r", encoding="utf-8") as f:
        script = session.create_script(f.read())
    script.load()
    device.resume(pid)
    print("App lanzada. Haz login normalmente.")

    # Espera a que se capture el Bearer y se guarde el log
    espera_log_y_bearer(timeout=90)
    print("¡Proceso terminado! Puedes cerrar la app si lo deseas.")

if __name__ == "__main__":
    main()