#!/usr/bin/env python3
import re
import json
from pathlib import Path
from collections import Counter
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
AUTH_LOG = BASE_DIR / "auth.log"
OUTPUT_JSON = BASE_DIR / "reporte_ssh.json"

FAILED_PATTERN = re.compile(
    r"Failed password.* from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
)

def analizar_auth_log():
    if not AUTH_LOG.exists():
        raise FileNotFoundError(f"No se encontró el archivo: {AUTH_LOG}")

    contador_ips = Counter()
    total_fallidos = 0

    with AUTH_LOG.open("r", encoding="utf-8", errors="ignore") as archivo:
        for linea in archivo:
            if "Failed password" in linea:
                total_fallidos += 1
                match = FAILED_PATTERN.search(linea)
                if match:
                    ip = match.group("ip")
                    contador_ips[ip] += 1

    top_10 = contador_ips.most_common(10)

    print("=" * 60)
    print("LAB 1.1 - Análisis de intentos fallidos SSH")
    print("=" * 60)
    print(f"Archivo analizado: {AUTH_LOG}")
    print(f"Total de intentos fallidos: {total_fallidos}")
    print("\nTop 10 IPs con más intentos fallidos:")

    for posicion, (ip, intentos) in enumerate(top_10, start=1):
        print(f"{posicion}. {ip} - {intentos} intentos")

    print("\nAlertas detectadas:")
    alertas = 0

    for ip, intentos in contador_ips.most_common():
        if intentos > 50:
            alertas += 1
            print(
                f"[ALERTA] IP: {ip} — {intentos} intentos fallidos — "
                "Posible ataque de fuerza bruta"
            )

    if alertas == 0:
        print("No se detectaron IPs con más de 50 intentos fallidos.")

    ips_sospechosas = [
        {
            "ip": ip,
            "intentos": intentos,
            "alerta": intentos > 50
        }
        for ip, intentos in contador_ips.most_common()
    ]

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total_fallidos,
        "ips_sospechosas": ips_sospechosas
    }

    with OUTPUT_JSON.open("w", encoding="utf-8") as archivo_json:
        json.dump(reporte, archivo_json, indent=4, ensure_ascii=False)

    print(f"\nReporte generado correctamente: {OUTPUT_JSON}")

if __name__ == "__main__":
    analizar_auth_log()
