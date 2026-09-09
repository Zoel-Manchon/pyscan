#!/usr/bin/env bash
# demo.sh — a paced walkthrough for recording the pyscan demo GIF.
#
#   ./demo.sh                 # (chmod +x demo.sh first, once)
#
# Start your screen recorder FIRST, then run this. It sets everything up, plays
# the beats with readable pauses, and ends in the OT command centre — press q to
# quit that, then stop the recorder.
#
# The story it tells, in order:
#   identify a service  ->  identify a PLC  ->  catch someone attacking it
#
# Set the terminal to ~110 columns and ~32 rows before recording. Narrower and
# the alert lines wrap mid-sentence, which reads badly in a looping GIF.
#
# Every beat degrades on its own: a missing optional dependency or no internet
# skips that beat with a one-line note instead of putting a traceback on camera.
#
# Knobs:
#   PAUSE=2.5 ./demo.sh          slower (default 1.6)
#   DEMO_TUI=sniff ./demo.sh     finish in the packet TUI instead
#   DEMO_TUI=none ./demo.sh      finish without a TUI at all
#   DEMO_NET=0 ./demo.sh         skip the beat that needs internet

cd "$(dirname "$0")" || exit 1

# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------
# Activate the project's venv if one is here and not already active. The layout
# differs by platform: bin/ on Linux and macOS, Scripts/ under Windows.
if ! command -v pyscan >/dev/null 2>&1; then
  for activate in .venv/bin/activate .venv/Scripts/activate; do
    if [ -f "$activate" ]; then
      # shellcheck disable=SC1090
      source "$activate"
      break
    fi
  done
fi
if ! command -v pyscan >/dev/null 2>&1; then
  echo "pyscan not found. From the project root:"
  echo "  python3 -m venv .venv"
  echo "  source .venv/bin/activate       # Windows: source .venv/Scripts/activate"
  echo "  pip install -e '.[dev,tui,lab]'"
  exit 1
fi

# Prefer plain `python`: once the venv is active that IS the venv's interpreter
# on every platform. `python3` does not exist inside a Windows venv, so asking
# for it first silently finds a system Python without this project installed —
# and the Modbus beat then skips itself for no visible reason.
PY=$(command -v python || command -v python3)
PAUSE="${PAUSE:-1.6}"
DEMO_TUI="${DEMO_TUI:-monitor}"
DEMO_NET="${DEMO_NET:-1}"

HMI=10.10.30.10
PLCS=10.10.30.21,10.10.40.7

# Run from a scratch directory, so the repo stays clean AND every command that
# appears on camera reads as a short relative path instead of /tmp/tmp.XkQ9…/
REPO=$(pwd)
WORK=$(mktemp -d)
CAPTURE=substation.pcap
REPORT=incident.md
SIM_PID=""
cd "$WORK" || exit 1

cleanup() {
  [ -n "$SIM_PID" ] && kill "$SIM_PID" 2>/dev/null
  cd "$REPO" 2>/dev/null || cd /
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

GREEN='\033[1;32m'; DIM='\033[2m'; YELLOW='\033[1;33m'; RESET='\033[0m'

say()  { printf "\n${DIM}# %s${RESET}\n" "$*"; sleep 1.0; }
skip() { printf "\n${YELLOW}# skipped: %s${RESET}\n" "$*"; sleep 1.0; }
run()  { printf "\n${GREEN}\$ ${RESET}%s\n" "$*"; sleep 0.4; "$@"; sleep "$PAUSE"; }
have() { "$PY" -c "import $1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# the demo
# ---------------------------------------------------------------------------
clear
printf "${DIM}# pyscan — port scanner, OT protocol identifier, ICS detection engine${RESET}\n"
sleep "$PAUSE"

# 1) the brand
run pyscan version

# 2) service and version detection against a host that exists to be scanned
if [ "$DEMO_NET" = "1" ]; then
  say "first half: what is listening, and what is it running?"
  run pyscan scan scanme.nmap.org -p 22,80,443
else
  skip "network beat disabled (DEMO_NET=0)"
fi

# 3) the same idea, aimed at OT — read-only, against a simulator
if have pymodbus; then
  say "same engine, an OT protocol: a simulated substation RTU"
  "$PY" "$REPO/tools/modbus_sim.py" >sim.log 2>&1 &
  SIM_PID=$!
  sleep 2.5                             # let the simulator bind its port
  run pyscan scan 127.0.0.1 -p 5020 --type modbus --max-rate 5
  say "vendor, product and firmware — read-only, never a write"
else
  skip "Modbus simulator needs pymodbus  (pip install -e '.[lab]')"
fi

# 4) the other half: the same protocol codecs, used to catch an attack
say "second half: the same codecs, now watching instead of asking"
run pyscan lab "$CAPTURE"

say "an unauthorised station writes to that PLC. watch what the rules make of it"
run pyscan monitor "$CAPTURE" --hmi "$HMI" --plc "$PLCS"

# 5) the artefact you hand over when the shift ends
say "and the report, with every finding on a timeline"
run pyscan monitor "$CAPTURE" --hmi "$HMI" --plc "$PLCS" --report "$REPORT"
sed -n '/## 3/,/## 4/p' "$REPORT" | head -n 12
sleep "$PAUSE"

# 6) the finale: a TUI, quit with q
case "$DEMO_TUI" in
  none)
    ;;
  sniff)
    if have textual; then
      printf "\n${GREEN}\$ ${RESET}pyscan sniff %s --tui   ${DIM}(press q to quit)${RESET}\n" "$CAPTURE"
      sleep 0.8
      pyscan sniff "$CAPTURE" --tui
    else
      skip "the TUI needs textual  (pip install -e '.[tui]')"
    fi
    ;;
  *)
    if have textual; then
      say "and the whole thing as a console: monitor, timeline, report"
      printf "\n${GREEN}\$ ${RESET}pyscan monitor %s --tui   ${DIM}(press q to quit)${RESET}\n" "$CAPTURE"
      sleep 0.8
      pyscan monitor "$CAPTURE" --hmi "$HMI" --plc "$PLCS" --tui
    else
      skip "the TUI needs textual  (pip install -e '.[tui]')"
    fi
    ;;
esac

printf "\n${DIM}# github.com/Zoel-Manchon/pyscan${RESET}\n"
