#!/usr/bin/env bash
# otkit.sh — one command, a menu, and everything the exercise needs.
#   chmod +x otkit.sh && ./otkit.sh
set -uo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
else echo "Docker with Compose is required (docker compose)."; exit 1; fi
RUN="$DC run --rm otkit"

pause(){ read -rp $'\nPress Enter to return to the menu... ' _; }
have_img(){ docker image inspect pyscan-otkit:latest >/dev/null 2>&1; }

while true; do
  clear
  cat <<'BANNER'
  ==================================================
    OT COMMAND  ·  blue team  ·  ICS exercise kit
  ==================================================
BANNER
  have_img && echo "  [image ready]" || echo "  [image NOT built -> press b first]"
  echo
  echo "  b) Build / refresh the Docker image"
  echo "  1) OT command centre, LIVE   (real capture off the NIC)"
  echo "  2) OT command centre, replay (practise against capture.pcap)"
  echo "  3) Generate a practice capture with an attack inside it"
  echo "  4) Mini-IDS in the terminal, live (no TUI)"
  echo "  5) pyscan sweep   (network inventory, throttled)"
  echo "  6) pyscan scan    (identify one host / PLC)"
  echo "  7) pyscan sniff --live --tui"
  echo "  8) Run the test suite"
  echo "  9) Shell inside the container"
  echo "  0) Quit"
  echo
  read -rp "  Option: " opt
  case "${opt:-}" in
    b) $DC build; pause;;
    1) read -rp "Interface [eth0]: " i; i=${i:-eth0}
       read -rp "HMI [10.10.30.10]: " h; h=${h:-10.10.30.10}
       read -rp "PLC/RTU [10.10.30.21,10.10.40.7]: " p; p=${p:-10.10.30.21,10.10.40.7}
       $RUN pyscan monitor --live --iface "$i" --hmi "$h" --plc "$p" --tui || true;;
    2) $RUN pyscan monitor capture.pcap --hmi 10.10.30.10 --plc 10.10.30.21,10.10.40.7 --tui || true;;
    3) $RUN pyscan lab capture.pcap || true; pause;;
    4) read -rp "Interface [eth0]: " i; i=${i:-eth0}
       read -rp "HMI [10.10.30.10]: " h; h=${h:-10.10.30.10}
       read -rp "PLC/RTU [10.10.30.21,10.10.40.7]: " p; p=${p:-10.10.30.21,10.10.40.7}
       $RUN pyscan monitor --live --iface "$i" --hmi "$h" --plc "$p" || true;;
    5) read -rp "Network CIDR [10.10.30.0/24]: " c; c=${c:-10.10.30.0/24}
       $RUN pyscan sweep "$c" --max-rate 5 || true; pause;;
    6) read -rp "Host / IP: " host
       read -rp "Port [502]: " pt; pt=${pt:-502}
       read -rp "Type (modbus/iec104/s7comm/tcp-connect) [modbus]: " ty; ty=${ty:-modbus}
       $RUN pyscan scan "$host" -p "$pt" --type "$ty" --max-rate 5 || true; pause;;
    7) read -rp "Interface [eth0]: " i; i=${i:-eth0}
       $RUN pyscan sniff --live --iface "$i" --tui || true;;
    8) $DC run --rm -v "$(pwd)":/repo -w /repo otkit sh -c "pip install -e '.[dev]' -q && pytest -q" || true; pause;;
    9) $RUN bash || true;;
    0) exit 0;;
    *) echo "  not a valid option"; sleep 1;;
  esac
done
