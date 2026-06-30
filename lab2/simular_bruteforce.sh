#!/bin/bash
# =============================================================================
# simular_bruteforce.sh
# Simula un ataque de fuerza bruta SSH para probar las reglas de correlación
# configuradas en Wazuh (Lab 2 — Evaluación Práctica).
#
# Uso:
#   bash simular_bruteforce.sh [IP_ATACANTE] [NUMERO_INTENTOS]
#
# Ejemplos:
#   bash simular_bruteforce.sh                        # valores por defecto
#   bash simular_bruteforce.sh 45.33.32.156 20        # 20 intentos desde IP dada
#
# Requisito: ejecutar como root o con sudo (para escribir en syslog via logger)
# =============================================================================

ATTACKER_IP="${1:-45.33.32.156}"
COUNT="${2:-15}"          # 15 intentos supera el umbral de 10 configurado en la regla
TARGET_USERS=("admin_db" "root" "ubuntu" "admin" "deploy" "postgres")
HOSTNAME_LOG="srv-prod-01"

echo "=============================================="
echo " Simulador de Fuerza Bruta SSH — Lab 2 Wazuh"
echo "=============================================="
echo " IP atacante  : $ATTACKER_IP"
echo " Intentos     : $COUNT"
echo " Intervalo    : 0.4s entre intentos (~$(echo "$COUNT * 4 / 10" | bc)s total)"
echo "----------------------------------------------"

for i in $(seq 1 "$COUNT"); do
    USER=${TARGET_USERS[$((RANDOM % ${#TARGET_USERS[@]}))]}
    PORT=$((RANDOM % 64511 + 1024))

    # Inyectar evento de fallo SSH en syslog (Wazuh lo lee desde /var/log/auth.log)
    logger -p auth.warning -t sshd \
        "Failed password for ${USER} from ${ATTACKER_IP} port ${PORT} ssh2"

    echo "  [+] Intento $i/$COUNT — Failed password for ${USER} from ${ATTACKER_IP} port ${PORT}"
    sleep 0.4
done

echo "----------------------------------------------"
echo " Simulación completada."
echo ""
echo " Verifique las alertas con:"
echo "   sudo tail -f /var/ossec/logs/alerts/alerts.log"
echo "   sudo grep '$ATTACKER_IP' /var/ossec/logs/alerts/alerts.log | tail -20"
echo ""
echo " Si la regla está correctamente configurada debería ver:"
echo "   Rule ID: 100001  |  Level: 10  |  brute_force"
