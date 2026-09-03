#!/usr/bin/env python3
"""
otwatch.py  ·  Mini-IDS OT (CLI) para Blue Team.  Usa el motor de otcore.py.

  Practica (pcap):   python3 otwatch.py capture.pcap
  En vivo (sudo):    sudo python3 otwatch.py --iface eth0
  Baseline propio:   python3 otwatch.py capture.pcap --hmi 10.10.30.10 --plc 10.10.30.21,10.10.40.7
"""
import sys, argparse
from otcore import Detector

class C:
    R="\033[91m"; Y="\033[93m"; G="\033[92m"; B="\033[96m"; DIM="\033[2m"; X="\033[0m"; BOLD="\033[1m"
if not sys.stdout.isatty():
    for k in list(vars(C)):
        if not k.startswith("_"): setattr(C, k, "")

def show(a):
    col = {"CRIT":C.R,"ALTO":C.R,"MEDIO":C.Y}.get(a["sev"], C.B)
    print(f'{col}{C.BOLD}[{a["sev"]:>5}]{C.X} {C.BOLD}{a["src"]:>15} -> {a["dst"]:<15}{C.X} {C.B}{a["proto"]}{C.X}  {a["what"]}')
    print(f'        {C.DIM}ATT&CK:{C.X} {a["attack"]}    {C.G}Accion:{C.X} {a["action"]}')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--iface")
    ap.add_argument("--hmi", default="10.10.30.10")
    ap.add_argument("--plc", default="10.10.30.21,10.10.40.7")
    a = ap.parse_args()
    det = Detector(a.hmi.split(","), a.plc.split(","))
    print(f"{C.BOLD}== otwatch · mini-IDS OT =={C.X}")
    print(f"   HMI baseline : {C.G}{', '.join(det.hmi)}{C.X}")
    print(f"   Protegiendo  : {C.Y}{', '.join(det.plcs)}{C.X}  (Modbus 502 · IEC-104 2404 · S7 102)\n")
    if a.iface:
        from scapy.all import sniff
        print(f"[*] Escuchando en {a.iface} ... CTRL-C para parar\n")
        sniff(iface=a.iface, store=False, filter="tcp port 502 or tcp port 2404 or tcp port 102",
              prn=lambda p: [show(x) for x in det.feed(p)])
    elif a.pcap:
        for al in det.from_pcap(a.pcap): show(al)
    else:
        ap.error("indica un .pcap o --iface")
    print(f'\n{C.BOLD}-- {det.packets} paquetes · {det.alerts} alertas --{C.X}')

if __name__ == "__main__":
    main()
