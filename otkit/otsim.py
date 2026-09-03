#!/usr/bin/env python3
"""
otsim.py  ·  Generador de trafico OT para practicar deteccion (Blue Team).

Crea un capture.pcap con:
  - Baseline legitimo: HMI -> PLC, solo lecturas Modbus (Func 3).
  - Ataque Modbus: host no autorizado hace recon + escrituras (Func 43/3/6/5).
  - Ataque IEC-104: interrogacion + comando de control (C_IC / C_SC) + STOPDT.

Abrelo en Wireshark y practica los filtros, o pasalo por otwatch.py.
Datos ficticios pero con bytes de protocolo correctos.

Uso:  python3 otsim.py            # crea capture.pcap
      python3 otsim.py salida.pcap
"""
import sys, struct
from scapy.all import Ether, IP, TCP, Raw, wrpcap

OUT = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"

HMI   = "10.10.30.10"     # <-- unico origen legitimo hacia el PLC (baseline)
PLC   = "10.10.30.21"     # PLC Modbus (feeder)
RTU   = "10.10.40.7"      # outstation IEC-104 (subestacion)
ATK   = "10.10.30.142"    # host del atacante (no deberia hablar con OT)

pkts = []
t = 1000.0  # tiempo base (epoch simplificado)

def push(src, dst, sport, dport, payload, flags="PA", dt=0.9):
    """Añade un paquete TCP con payload de aplicacion y avanza el reloj."""
    global t
    p = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags=flags)/Raw(load=bytes(payload))
    p.time = t
    t += dt
    pkts.append(p)

# ---------- Modbus TCP (puerto 502) ----------
def mbap(unit, pdu):
    """MBAP header + PDU.  Length = unit(1) + len(pdu)."""
    return struct.pack(">HHHB", 0, 0, len(pdu) + 1, unit) + pdu

def modbus_read(unit=1, addr=0, qty=125):        # FC 3 lectura (normal)
    return mbap(unit, struct.pack(">BHH", 0x03, addr, qty))
def modbus_devid(unit=1):                         # FC 43/14 Read Device ID (recon)
    return mbap(unit, bytes([0x2B, 0x0E, 0x01, 0x00]))
def modbus_write_reg(unit=1, addr=9, val=250):    # FC 6 Write Single Register (sabotaje)
    return mbap(unit, struct.pack(">BHH", 0x06, addr, val))
def modbus_write_coil(unit=1, addr=0, on=False):  # FC 5 Write Single Coil (abre interruptor)
    return mbap(unit, struct.pack(">BHH", 0x05, addr, 0xFF00 if on else 0x0000))

# ---------- IEC 60870-5-104 (puerto 2404) ----------
def iec_iformat(asdu):
    """APCI I-format (control 00 00 00 00) + ASDU."""
    body = b"\x00\x00\x00\x00" + asdu
    return bytes([0x68, len(body)]) + body
def iec_uformat(ctrl):                            # STARTDT=0x07, STOPDT=0x13, TESTFR=0x43
    return bytes([0x68, 0x04, ctrl, 0x00, 0x00, 0x00])
def iec_asdu(typeid, cot=6, ca=1, ioa=1, obj=b"\x01"):
    return struct.pack("<BBHH", typeid, 0x01, cot, ca) + struct.pack("<I", ioa)[:3] + obj
def iec_interrogation():                          # C_IC_NA_1 (100) interrogacion general (recon)
    return iec_iformat(iec_asdu(100, ioa=0, obj=b"\x14"))
def iec_single_cmd():                             # C_SC_NA_1 (45) comando unico (sabotaje)
    return iec_iformat(iec_asdu(45, ioa=1, obj=b"\x01"))

# ================= ESCENA =================
# 1) Baseline legitimo: HMI sondea el PLC con lecturas
for i in range(6):
    push(HMI, PLC, 50100 + i, 502, modbus_read(addr=i * 10))
    push(PLC, HMI, 502, 50100 + i, modbus_read(addr=i * 10), dt=0.2)

# 2) Atacante entra: conexion nueva + recon Modbus
push(ATK, PLC, 50412, 502, b"", flags="S", dt=0.3)       # SYN (talker nuevo)
push(ATK, PLC, 50412, 502, modbus_devid())                # FC 43 recon
push(ATK, PLC, 50412, 502, modbus_read(addr=0,   qty=125))# barrido de tags
push(ATK, PLC, 50412, 502, modbus_read(addr=125, qty=125))

# 3) Sabotaje Modbus: cambia consigna y abre el interruptor
push(ATK, PLC, 50412, 502, modbus_write_reg(addr=9, val=250))   # FC 6 (Modify Parameter)
push(ATK, PLC, 50412, 502, modbus_write_coil(addr=0, on=False)) # FC 5 (abre feeder)
push(PLC, ATK, 502, 50412, modbus_write_coil(addr=0, on=False), dt=0.2)  # PLC confirma

# 4) Ataque IEC-104 sobre la subestacion
push(ATK, RTU, 51020, 2404, iec_interrogation())   # recon (interrogacion)
push(ATK, RTU, 51020, 2404, iec_single_cmd())      # C_SC comando de control (Industroyer-style)
push(ATK, RTU, 51020, 2404, iec_uformat(0x13))     # STOPDT: intenta cortar el reporte

wrpcap(OUT, pkts)
print(f"[+] {len(pkts)} paquetes escritos en {OUT}")
print(f"    Baseline HMI={HMI}  PLC={PLC}  RTU={RTU}  Atacante={ATK}")
print(f"    Abrelo:  wireshark {OUT}    o    python3 otwatch.py {OUT}")
