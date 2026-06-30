#!/usr/bin/env python3
import re
import json
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter, deque
from urllib.parse import unquote, urlsplit

BASE_DIR = Path(__file__).resolve().parent
ACCESS_LOG = BASE_DIR / "access.log"
OUTPUT_JSON = BASE_DIR / "reporte_web.json"

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<url>\S+) (?P<protocolo>[^"]+)" '
    r'(?P<codigo>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

SQLI_PATTERNS = ["UNION", "SELECT", "--", "OR 1=1", "'"]

def parsear_fecha(fecha_txt):
    try:
        return datetime.strptime(fecha_txt, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

def obtener_ruta(url):
    try:
        url_decodificada = unquote(url)
        return urlsplit(url_decodificada).path or url_decodificada
    except Exception:
        return url

def detectar_sqli(url):
    url_decodificada = unquote(url)
    url_mayuscula = url_decodificada.upper()
    patrones = []

    for patron in SQLI_PATTERNS:
        if patron in url_mayuscula:
            patrones.append(patron)

    return patrones

def analizar_access_log():
    if not ACCESS_LOG.exists():
        raise FileNotFoundError(f"No se encontró el archivo: {ACCESS_LOG}")

    eventos = []
    errores_por_ip = defaultdict(Counter)
    intentos_sqli = []
    total_lineas = 0
    lineas_parseadas = 0

    with ACCESS_LOG.open("r", encoding="utf-8", errors="ignore") as archivo:
        for linea in archivo:
            total_lineas += 1
            match = LOG_PATTERN.search(linea)

            if not match:
                continue

            lineas_parseadas += 1

            ip = match.group("ip")
            fecha = parsear_fecha(match.group("fecha"))
            metodo = match.group("metodo")
            url = match.group("url")
            codigo = int(match.group("codigo"))
            ruta = unquote(url)

            evento = {
                "ip": ip,
                "fecha": fecha,
                "metodo": metodo,
                "url": url,
                "ruta": ruta,
                "codigo": codigo,
                "user_agent": match.group("user_agent")
            }

            eventos.append(evento)

            if 400 <= codigo <= 599:
                errores_por_ip[ip][str(codigo)] += 1

            patrones_sqli = detectar_sqli(url)
            if patrones_sqli:
                intentos_sqli.append({
                    "ip": ip,
                    "fecha": fecha.strftime("%Y-%m-%d %H:%M:%S %z") if fecha else None,
                    "metodo": metodo,
                    "url": url,
                    "codigo": codigo,
                    "patrones_detectados": patrones_sqli
                })

    eventos_por_ip = defaultdict(list)

    for evento in eventos:
        if evento["fecha"] is not None:
            eventos_por_ip[evento["ip"]].append(evento)

    escaneos_detectados = []

    for ip, lista_eventos in eventos_por_ip.items():
        lista_eventos.sort(key=lambda x: x["fecha"])
        ventana = deque()
        rutas_en_ventana = Counter()
        max_rutas_distintas = 0
        mejor_inicio = None
        mejor_fin = None

        for evento in lista_eventos:
            ventana.append(evento)
            rutas_en_ventana[evento["ruta"]] += 1

            while ventana and evento["fecha"] - ventana[0]["fecha"] > timedelta(seconds=60):
                evento_antiguo = ventana.popleft()
                rutas_en_ventana[evento_antiguo["ruta"]] -= 1
                if rutas_en_ventana[evento_antiguo["ruta"]] <= 0:
                    del rutas_en_ventana[evento_antiguo["ruta"]]

            rutas_distintas = len(rutas_en_ventana)

            if rutas_distintas > max_rutas_distintas:
                max_rutas_distintas = rutas_distintas
                mejor_inicio = ventana[0]["fecha"]
                mejor_fin = ventana[-1]["fecha"]

        if max_rutas_distintas > 20:
            escaneos_detectados.append({
                "ip": ip,
                "rutas_distintas_en_60s": max_rutas_distintas,
                "inicio": mejor_inicio.strftime("%Y-%m-%d %H:%M:%S %z"),
                "fin": mejor_fin.strftime("%Y-%m-%d %H:%M:%S %z"),
                "alerta": True
            })

    errores_http_por_ip = []

    for ip, contador_codigos in errores_por_ip.items():
        total_errores = sum(contador_codigos.values())
        errores_http_por_ip.append({
            "ip": ip,
            "total_errores_4xx_5xx": total_errores,
            "codigos": dict(contador_codigos)
        })

    errores_http_por_ip.sort(key=lambda x: x["total_errores_4xx_5xx"], reverse=True)

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "archivo_analizado": str(ACCESS_LOG),
        "total_lineas": total_lineas,
        "lineas_parseadas": lineas_parseadas,
        "total_eventos_http": len(eventos),
        "escaneos_directorios": escaneos_detectados,
        "errores_http_por_ip": errores_http_por_ip,
        "intentos_sqli": intentos_sqli
    }

    with OUTPUT_JSON.open("w", encoding="utf-8") as archivo_json:
        json.dump(reporte, archivo_json, indent=4, ensure_ascii=False)

    print("=" * 60)
    print("LAB 1.2 - Análisis de access.log")
    print("=" * 60)
    print(f"Archivo analizado: {ACCESS_LOG}")
    print(f"Total de líneas: {total_lineas}")
    print(f"Líneas parseadas: {lineas_parseadas}")

    print("\nEscaneos de directorios detectados:")
    if escaneos_detectados:
        for escaneo in escaneos_detectados:
            print(
                f"[ALERTA] IP: {escaneo['ip']} - "
                f"{escaneo['rutas_distintas_en_60s']} rutas distintas en menos de 60 segundos"
            )
    else:
        print("No se detectaron escaneos de directorios.")

    print("\nTop IPs con errores HTTP 4xx/5xx:")
    for item in errores_http_por_ip[:10]:
        print(f"{item['ip']} - {item['total_errores_4xx_5xx']} errores - {item['codigos']}")

    print("\nIntentos de SQL Injection detectados:")
    if intentos_sqli:
        for intento in intentos_sqli[:20]:
            print(
                f"[SQLi] IP: {intento['ip']} - "
                f"Patrones: {', '.join(intento['patrones_detectados'])} - "
                f"URL: {intento['url']}"
            )
    else:
        print("No se detectaron intentos de SQL Injection.")

    print(f"\nReporte generado correctamente: {OUTPUT_JSON}")

if __name__ == "__main__":
    analizar_access_log()
