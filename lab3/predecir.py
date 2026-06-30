#!/usr/bin/env python3
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "modelo_anomalias.pkl"

def preparar_features(df, feature_columns):
    df_proc = df.copy()

    df_proc["timestamp"] = pd.to_datetime(df_proc["timestamp"])

    df_proc["total_bytes"] = df_proc["bytes_sent"] + df_proc["bytes_recv"]
    df_proc["ratio_bytes"] = df_proc["bytes_sent"] / (df_proc["bytes_recv"] + 1)
    df_proc["bytes_por_segundo"] = df_proc["total_bytes"] / (df_proc["duration_sec"] + 1)
    df_proc["packets_por_segundo"] = df_proc["packets"] / (df_proc["duration_sec"] + 1)
    df_proc["hour"] = df_proc["timestamp"].dt.hour

    features = pd.get_dummies(
        df_proc[[
            "dst_port", "protocol", "bytes_sent", "bytes_recv",
            "duration_sec", "packets", "total_bytes", "ratio_bytes",
            "bytes_por_segundo", "packets_por_segundo", "hour"
        ]],
        columns=["protocol"],
        drop_first=False
    )

    features = features.reindex(columns=feature_columns, fill_value=0)
    return features

def main():
    if len(sys.argv) != 2:
        print("Uso: python predecir.py nuevo_trafico.csv")
        sys.exit(1)

    input_csv = Path(sys.argv[1])

    if not input_csv.exists():
        print(f"[ERROR] No existe el archivo: {input_csv}")
        sys.exit(1)

    if not MODEL_PATH.exists():
        print(f"[ERROR] No existe el modelo: {MODEL_PATH}")
        sys.exit(1)

    artefacto = joblib.load(MODEL_PATH)

    model = artefacto["model"]
    scaler = artefacto["scaler"]
    feature_columns = artefacto["feature_columns"]
    threshold = artefacto["threshold"]

    df = pd.read_csv(input_csv)
    features = preparar_features(df, feature_columns)
    X_scaled = scaler.transform(features)

    scores_raw = model.decision_function(X_scaled)
    anomaly_score = -scores_raw

    df_resultado = df.copy()
    df_resultado["anomaly_score"] = anomaly_score
    df_resultado["prediccion"] = np.where(
        df_resultado["anomaly_score"] >= threshold,
        "anomaly",
        "normal"
    )

    anomalias = df_resultado[df_resultado["prediccion"] == "anomaly"]

    print("=" * 70)
    print("Predicción de anomalías de tráfico de red")
    print("=" * 70)
    print(f"Archivo analizado: {input_csv}")
    print(f"Registros analizados: {len(df_resultado)}")
    print(f"Umbral usado: {threshold:.6f}")
    print(f"Anomalías detectadas: {len(anomalias)}")

    if len(anomalias) > 0:
        print("\nRegistros clasificados como anomalía:")
        print(anomalias.sort_values("anomaly_score", ascending=False).to_string(index=False))
    else:
        print("\nNo se detectaron anomalías con el umbral actual.")
        print("\nTop 10 registros con mayor score para revisión:")
        print(
            df_resultado
            .sort_values("anomaly_score", ascending=False)
            .head(10)
            .to_string(index=False)
        )

if __name__ == "__main__":
    main()
