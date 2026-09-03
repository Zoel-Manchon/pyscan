#!/usr/bin/env python3
"""
otcore.py  ·  Motor de deteccion OT compartido (Blue Team).

Analiza Modbus / IEC-104 / S7comm y devuelve alertas ESTRUCTURADAS (dicts),
para que las use tanto el CLI (otwatch.py) como la TUI (ot_command.py).

Cada alerta:
  {sev, src, dst, proto, what, attack, action}
  sev in {CRIT, ALTO, MEDIO}
"""
from scapy.all import IP, TCP, Raw, rdpcap

MODBUS_WRITE = {5:"Write Single Coil",6:"Write Single Register",
                15:"Write Multiple Coils",16:"Write Multiple Registers"}
MODBUS_RECON = {43:"Read Device ID",8:"Diagnostics",17:"Report Server ID"}
IEC_CMD = {45:"C_SC single cmd",46:"C_DC double cmd",47:"C_RC step",
           48:"C_SE setpoint NVA",49:"C_SE setpoint SVA",50:"C_SE setpoint short",
           51:"C_BO bitstring",100:"C_IC interrogation",101:"C_CI counter interr",
           105:"C_RP reset process"}
OT_PORTS = (502, 2404, 102)


class Detector:
    """Alimentalo con paquetes scapy (feed) o con un pcap (from_pcap)."""

    def __init__(self, hmi, plcs):
        self.hmi = set(x.strip() for x in hmi if x.strip())
        self.plcs = set(x.strip() for x in plcs if x.strip())
        self.talkers = {}                 # ip -> set(plc) ya avisados
        self.packets = 0
        self.alerts = 0
        self.seen_src = set()             # IOC: origenes hostiles
        self.seen_fc = set()              # IOC: funciones/typeids vistos

    # -- helpers de alerta --
    def _a(self, sev, src, dst, proto, what, attack, action):
        self.alerts += 1
        return {"sev": sev, "src": src, "dst": dst, "proto": proto,
                "what": what, "attack": attack, "action": action}

    def _talker(self, src, dst):
        out = []
        if dst in self.plcs and src not in self.hmi:
            seen = self.talkers.setdefault(src, set())
            if dst not in seen:
                seen.add(dst)
                self.seen_src.add(src)
                out.append(self._a("ALTO", src, dst, "OT",
                    "Talker NO autorizado hacia un PLC/RTU (fuera de baseline)",
                    "Discovery / Lateral Movement",
                    "Aisla el ORIGEN por ACL en la IDMZ; el HMI deberia ser el unico permitido"))
        return out

    def _modbus(self, src, dst, pay):
        # payload = MBAP (7 bytes) + PDU; FC en offset 7
        if len(pay) < 8:
            return []
        fc = pay[7]
        if fc in MODBUS_WRITE:
            self.seen_fc.add(f"Modbus FC{fc}")
            return [self._a("CRIT", src, dst, "Modbus", f"ESCRITURA Func {fc}: {MODBUS_WRITE[fc]}",
                "Impair Process Control / Unauthorized Command Message",
                "Confirma origen != HMI. Aisla origen. NO reinicies el PLC; coordina reposicion")]
        if fc in MODBUS_RECON:
            self.seen_fc.add(f"Modbus FC{fc}")
            return [self._a("MEDIO", src, dst, "Modbus", f"Recon Func {fc}: {MODBUS_RECON[fc]}",
                "Discovery / Collection", "Vigila este origen: suele preceder a la escritura")]
        return []

    def _iec(self, src, dst, payload):
        out, i = [], 0
        while i + 1 < len(payload) and payload[i] == 0x68:
            ln = payload[i + 1]
            apdu = payload[i:i + 2 + ln]
            if len(apdu) < 6:
                break
            ctrl0 = apdu[2]
            if ctrl0 & 0x01 == 0:                      # I-format -> ASDU
                if len(apdu) >= 7:
                    tid = apdu[6]
                    if tid in IEC_CMD:
                        cmd = tid < 100
                        self.seen_fc.add(f"IEC-104 T{tid}")
                        out.append(self._a(
                            "CRIT" if cmd else "MEDIO", src, dst, "IEC-104",
                            f"{'COMANDO DE CONTROL' if cmd else 'Recon (interrogacion)'} TypeID {tid}: {IEC_CMD[tid]}",
                            ("Impair Process Control / Unauthorized Command Message"
                             if cmd else "Discovery / Collection"),
                            ("Comando legitimo de origen ilegitimo = firma Industroyer. "
                             "Aisla origen; NO cortes el proceso") if cmd
                            else "Interrogacion desde origen no-HMI: suele preceder al comando"))
            elif ctrl0 & 0x03 == 0x03 and ctrl0 == 0x13:  # STOPDT act
                out.append(self._a("MEDIO", src, dst, "IEC-104",
                    "STOPDT act: intento de cortar el reporte",
                    "Inhibit Response Function / Block Reporting Message",
                    "Alguien silencia la telemetria: correlaciona con comandos previos"))
            i += 2 + ln
        return out

    def _s7(self, src, dst, payload):
        if len(payload) >= 8 and payload[0] == 0x03 and 0x32 in payload[:12]:
            self.seen_fc.add("S7 job")
            return [self._a("MEDIO", src, dst, "S7comm",
                "Trafico S7 job (posible write/stop/download de bloque)",
                "Execution / Impair Process Control",
                "Revisa en Wireshark s7comm.param.func; confirma origen")]
        return []

    # -- API principal --
    def feed(self, pkt):
        """Devuelve lista de alertas para un paquete scapy."""
        if not (pkt.haslayer(TCP) and pkt.haslayer(IP)):
            return []
        self.packets += 1
        ip, tcp = pkt[IP], pkt[TCP]
        src, dst, dport = ip.src, ip.dst, int(tcp.dport)
        out = []
        if str(tcp.flags) == "S" and dport in OT_PORTS and dst in self.plcs and src not in self.hmi:
            out.append(self._a("MEDIO", src, dst, "TCP",
                f"Conexion nueva (SYN) al puerto OT {dport}",
                "Discovery / Initial Access", "Talker nuevo hacia OT: vigilalo"))
        pay = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        if dport == 502 and pay:
            out += self._talker(src, dst) + self._modbus(src, dst, pay)
        elif dport == 2404 and pay:
            out += self._talker(src, dst) + self._iec(src, dst, pay)
        elif dport == 102 and pay:
            out += self._talker(src, dst) + self._s7(src, dst, pay)
        return out

    def from_pcap(self, path):
        """Itera alertas de un fichero pcap."""
        for p in rdpcap(path):
            for a in self.feed(p):
                yield a
