import os
import urllib.request
import zipfile
import shutil
import sys
import json
import re

try:
    import lzma
except ImportError:
    lzma = None

def get_latest_github_asset(repo, pattern):
    """Devuelve (url, nombre_archivo) del primer asset que coincida con el patrón en el último release."""
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        with urllib.request.urlopen(api_url) as resp:
            data = json.load(resp)
            for asset in data.get("assets", []):
                if re.search(pattern, asset["name"]):
                    return asset["browser_download_url"], asset["name"]
    except Exception as e:
        print(f"  ✖ ERROR al consultar {repo}: {e}")
    return None, None


# Descargas necesarias (solo ADB y frida-server)
descargas = [
    {
        "carpeta": "platform-tools",
        "url": "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
        "nombre": "platform-tools-latest-windows.zip",
        "descomprimir": True,
        "tipo": "zip"
    },
    {
        "carpeta": "frida",
        "url": "https://github.com/frida/frida/releases/download/16.5.6/frida-server-16.5.6-android-x86_64.xz",
        "nombre": "frida-server.xz",
        "descomprimir": True,
        "tipo": "xz"
    }
]

def descargar(url, ruta_destino):
    print(f"Descargando {url} ...")
    try:
        urllib.request.urlretrieve(url, ruta_destino)
        print(f"  ✔ Guardado en {ruta_destino}")
        return True
    except Exception as e:
        print(f"  ✖ ERROR al descargar {url}: {e}")
        return False

def descomprimir_zip(ruta_zip, carpeta_destino):
    print(f"Descomprimiendo {ruta_zip} en {carpeta_destino} ...")
    try:
        with zipfile.ZipFile(ruta_zip, 'r') as zip_ref:
            zip_ref.extractall(carpeta_destino)
        print(f"  ✔ Descomprimido correctamente.")
        return True
    except Exception as e:
        print(f"  ✖ ERROR al descomprimir {ruta_zip}: {e}")
        return False

def descomprimir_xz(ruta_xz, carpeta_destino):
    if lzma is None:
        print("  ✖ ERROR: El módulo lzma no está disponible en tu instalación de Python.")
        print("    Instala Python 3.3+ o instala el módulo lzma.")
        return False
    print(f"Descomprimiendo {ruta_xz} en {carpeta_destino} ...")
    try:
        output_file = os.path.join(carpeta_destino, "frida-server")
        with lzma.open(ruta_xz) as f_in, open(output_file, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        print(f"  ✔ Descomprimido correctamente como {output_file}")
        return True
    except Exception as e:
        print(f"  ✖ ERROR al descomprimir {ruta_xz}: {e}")
        return False

def main():
    errores = []
    for d in descargas:
        carpeta = d["carpeta"]
        if not os.path.exists(carpeta):
            os.makedirs(carpeta)
        ruta = os.path.join(carpeta, d["nombre"])
        print(f"\n--- Procesando {d['nombre']} ---")
        if os.path.exists(ruta):
            print(f"  (Ya existe {ruta}, omitiendo descarga)")
        else:
            if not descargar(d["url"], ruta):
                errores.append(f"Descarga fallida: {d['nombre']}")
                continue
        if d["descomprimir"]:
            if d["tipo"] == "zip":
                if not descomprimir_zip(ruta, carpeta):
                    errores.append(f"Descompresión fallida: {d['nombre']}")
            elif d["tipo"] == "xz":
                if not descomprimir_xz(ruta, carpeta):
                    errores.append(f"Descompresión fallida: {d['nombre']}")
    print("\nResumen de la operación:")
    if errores:
        print("✖ Hubo errores en los siguientes archivos:")
        for err in errores:
            print("  -", err)
    else:
        print("✔ Todo descargado y descomprimido correctamente.")
    print("\nRevisa las carpetas y sigue la guía para flashear/instalar en el emulador.")
    print("Si algún archivo falló, descárgalo manualmente desde los enlaces oficiales.")

if __name__ == "__main__":
    main()