#!/usr/bin/env bash
# demo.sh — a paced walkthrough for recording the pyscan demo GIF.
#
# Usage:
#   source .venv/bin/activate     # make sure the venv is active
#   ./demo.sh                      # (chmod +x demo.sh first, once)
#
# Start your screen recorder (Peek) FIRST, then run this. It auto-starts the
# Modbus simulator, runs the four demo beats with readable pauses, and ends in
# the live TUI — press q to quit the TUI, then stop the recorder.
#
# Tweak the pace:  PAUSE=2 ./demo.sh

cd "$(dirname "$0")" || exit 1

# Use the project's virtualenv automatically if it's here and not already active.
if ! command -v pyscan >/dev/null 2>&1 && [ -f .venv/bin/activate ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi
if ! command -v pyscan >/dev/null 2>&1; then
  echo "pyscan not found. Put demo.sh in the project root, then set up the venv:"
  echo "  cd ~/Documents/labs/pyscan"
  echo "  python3 -m venv .venv && source .venv/bin/activate && pip install -e '.[dev,tui,lab]'"
  exit 1
fi

GREEN='\033[1;32m'; DIM='\033[2m'; RESET='\033[0m'
PAUSE="${PAUSE:-1.6}"

run() {
  printf "\n${GREEN}\$ ${RESET}%s\n" "$*"
  sleep 0.4
  "$@"
  sleep "$PAUSE"
}

clear
printf "${DIM}# pyscan — modular port & OT-protocol scanner${RESET}\n"
sleep "$PAUSE"

# 1) the brand
run pyscan version

# 2) a real scan with service/version detection (needs internet)
run pyscan scan scanme.nmap.org -p 22,80,443

# 3) OT: identify the simulated substation RTU (sim auto-started below)
python3 tools/modbus_sim.py >/tmp/pyscan_demo_sim.log 2>&1 &
SIM_PID=$!
trap 'kill "$SIM_PID" 2>/dev/null' EXIT
sleep 2.5  # let the simulator come up
run pyscan scan 127.0.0.1 -p 5020 --type modbus

# 4) the finale: the live packet TUI (press q to quit)
printf "\n${GREEN}\$ ${RESET}pyscan sniff sample.pcap --tui   ${DIM}(press q to quit)${RESET}\n"
sleep 0.6
pyscan sniff sample.pcap --tui

printf "\n${DIM}# done — github.com/Zoel-Manchon/pyscan${RESET}\n"
