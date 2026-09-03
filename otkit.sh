#!/usr/bin/env bash
# otkit.sh — centro de mando por menú. Un solo comando y eliges qué hacer.
#   chmod +x otkit.sh   &&   ./otkit.sh
set -uo pipefail
cd "$(dirname "$0")"

# --- detectar Docker Compose ---
if docker compose version >/dev/null 2>&1; then DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
else echo "Necesitas Docker con Compose (docker compose)."; exit 1; fi
RUN="$DC run --rm otkit"

pause(){ read -rp $'\nEnter para volver al menú... ' _; }
have_img(){ docker image inspect pyscan-otkit:latest >/dev/null 2>&1; }

while true; do
  clear
  cat <<'BANNER'
  ==================================================
    OT COMMAND  ·  Blue Team OT  ·  centro de mando
  ==================================================
BANNER
  have_img && echo "  [imagen lista]" || echo "  [imagen NO construida -> pulsa b primero]"
  echo
  echo "  b) Construir / actualizar la imagen Docker"
  echo "  1) TUI centro de mando   (EN VIVO: sniff real de la NIC)"
  echo "  2) TUI centro de mando   (practica: dentro pulsa Replay pcap)"
  echo "  3) Generar captura de ejemplo (otsim -> capture.pcap)"
  echo "  4) Watch CLI en vivo (mini-IDS sin TUI)"
  echo "  5) pyscan sweep   (inventario de la red)"
  echo "  6) pyscan scan    (identificar un host / PLC)"
  echo "  7) pyscan sniff --live --tui"
  echo "  8) Ejecutar tests"
  echo "  9) Shell dentro del contenedor"
  echo "  0) Salir"
  echo
  read -rp "  Opcion: " opt
  case "${opt:-}" in
    b) $DC build; pause;;
    1|2) $RUN python ot_command.py || true;;
    3) $RUN python otsim.py || true; pause;;
    4) read -rp "Interfaz [eth0]: " i; i=${i:-eth0}
       read -rp "HMI [10.10.30.10]: " h; h=${h:-10.10.30.10}
       read -rp "PLC/RTU [10.10.30.21,10.10.40.7]: " p; p=${p:-10.10.30.21,10.10.40.7}
       $RUN python otwatch.py --iface "$i" --hmi "$h" --plc "$p" || true;;
    5) read -rp "Red CIDR [10.10.30.0/24]: " c; c=${c:-10.10.30.0/24}
       $RUN pyscan sweep "$c" || true; pause;;
    6) read -rp "Host / IP: " host
       read -rp "Puerto [502]: " pt; pt=${pt:-502}
       read -rp "Tipo (modbus/iec104/s7comm/tcp-connect) [modbus]: " ty; ty=${ty:-modbus}
       $RUN pyscan scan "$host" -p "$pt" --type "$ty" --max-rate 5 || true; pause;;
    7) read -rp "Interfaz [eth0]: " i; i=${i:-eth0}
       $RUN pyscan sniff --live --iface "$i" --tui || true;;
    8) $DC run --rm -v "$(pwd)":/repo -w /repo otkit pytest -q || true; pause;;
    9) $RUN bash || true;;
    0) exit 0;;
    *) echo "  opcion no valida"; sleep 1;;
  esac
done
