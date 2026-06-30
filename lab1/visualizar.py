#!/usr/bin/env python3
import re
import json
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

BASE_DIR = Path(__file__).resolve().parent
AUTH_LOG = BASE_DIR / "auth.log"
ACCESS_LOG = BASE_DIR / "access.log"
GRAFICAS_DIR = BASE_DIR / "graficas"

GRAFICAS_DIR.mkdir(exist_ok=True)

FAILED_PATTERN = re.compile(
    r"Failed password.* from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
)

ACCESS_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<url>\S+) (?P<protocolo>[^"]+)" '
    r'(?P<codigo>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

def parsear_fecha_apache(fecha_txt):
    return datetime.strptime(fecha_txt, "%d/%b/%Y:%H:%M:%S %z")

def grafico_top10_ssh():
    contador = Counter()

    with AUTH_LOG.open("r", encoding="utf-8", errors="ignore") as archivo:
        for linea in archivo:
            if "Failed password" in linea:
                match = FAILED_PATTERN.search(linea)
                if match:
                    contador[match.group("ip")] += 1

    top10 = contador.most_common(10)
    ips = [item[0] for item in top10]
    intentos = [item[1] for item in top10]

    plt.figure(figsize=(12, 6))
    plt.bar(ips, intentos)
    plt.title("Top 10 IPs con más intentos fallidos SSH")
    plt.xlabel("Dirección IP")
    plt.ylabel("Intentos fallidos")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(GRAFICAS_DIR / "top10_ssh.png", dpi=150)
    plt.close()

def cargar_access_log():
    registros = []

    with ACCESS_LOG.open("r", encoding="utf-8", errors="ignore") as archivo:
        for linea in archivo:
            match = ACCESS_PATTERN.search(linea)
            if not match:
                continue

            fecha = parsear_fecha_apache(match.group("fecha"))
            codigo = int(match.group("codigo"))

            registros.append({
                "ip": match.group("ip"),
                "fecha": fecha,
                "hora": fecha.strftime("%Y-%m-%d %H:00"),
                "codigo": codigo,
                "url": match.group("url")
            })

    return pd.DataFrame(registros)

def grafico_timeline_http(df):
    peticiones_por_hora = df.groupby("hora").size().reset_index(name="peticiones")
    peticiones_por_hora["hora"] = pd.to_datetime(peticiones_por_hora["hora"])

    plt.figure(figsize=(12, 6))
    plt.plot(peticiones_por_hora["hora"], peticiones_por_hora["peticiones"], marker="o")
    plt.title("Número de peticiones HTTP por hora")
    plt.xlabel("Hora")
    plt.ylabel("Cantidad de peticiones")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(GRAFICAS_DIR / "timeline_http.png", dpi=150)
    plt.close()

def grafico_heatmap_http(df):
    codigos_interes = [200, 301, 404, 500]
    df_filtrado = df[df["codigo"].isin(codigos_interes)].copy()

    tabla = pd.pivot_table(
        df_filtrado,
        index="hora",
        columns="codigo",
        values="ip",
        aggfunc="count",
        fill_value=0
    )

    for codigo in codigos_interes:
        if codigo not in tabla.columns:
            tabla[codigo] = 0

    tabla = tabla[codigos_interes]

    plt.figure(figsize=(10, 8))
    sns.heatmap(tabla, annot=True, fmt="d")
    plt.title("Heatmap de peticiones HTTP por hora y código de respuesta")
    plt.xlabel("Código HTTP")
    plt.ylabel("Hora")
    plt.tight_layout()
    plt.savefig(GRAFICAS_DIR / "heatmap_http.png", dpi=150)
    plt.close()

def main():
    print("=" * 60)
    print("LAB 1.3 - Generación de visualizaciones")
    print("=" * 60)

    grafico_top10_ssh()
    print("[OK] Gráfico generado: lab1/graficas/top10_ssh.png")

    df = cargar_access_log()
    grafico_timeline_http(df)
    print("[OK] Gráfico generado: lab1/graficas/timeline_http.png")

    grafico_heatmap_http(df)
    print("[OK] Gráfico generado: lab1/graficas/heatmap_http.png")

    print("\nVisualizaciones generadas correctamente.")

if __name__ == "__main__":
    main()
