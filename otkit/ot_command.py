#!/usr/bin/env python3
"""
ot_command.py  ·  OT COMMAND — centro de mando Blue Team (TUI Textual).

Todo a mano para el ejercicio:
  · Monitor en vivo (motor otcore): alerta de escrituras/comandos OT en tiempo real
  · Timeline con timestamps UTC + exportacion de informe en Markdown
  · Referencia: filtros Wireshark/tshark, los 6 ataques, ATT&CK for ICS, respuesta
  · Comandos listos de pyscan (inventario/sniff) y nmap seguro

Ejecutar:
  pip install textual scapy --break-system-packages
  python3 ot_command.py                 # arranca la TUI
  (para captura en vivo dentro de la TUI necesitas lanzarla con sudo)

Teclas: [q] salir · raton o Tab para navegar · botones para todo.
"""
from datetime import datetime, timezone

from otcore import Detector
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import Button, DataTable, Footer, Header, Input, RichLog, Static, TabbedContent, TabPane

SEV_COLOR = {"CRIT": "red", "ALTO": "red", "MEDIO": "yellow"}


def utcnow():
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


# ---------- textos de referencia ----------
FILTERS = """[b yellow]FILTROS WIRESHARK[/]  (barra de display filter)
[cyan]modbus.func_code >= 5 && modbus.func_code <= 16[/]   escrituras Modbus
[cyan]104asdu.typeid >= 45 && 104asdu.typeid <= 51[/]      comandos IEC-104
[cyan]dnp3.al.func == 4 || dnp3.al.func == 5[/]             control DNP3
[cyan]s7comm.param.func[/]                                  funciones S7
[cyan]tcp.flags.syn==1 && tcp.flags.ack==0[/]               escaneo (SYN)
[cyan]telnet || ftp || http.authorization[/]               credenciales en claro
[cyan]ip.dst==<PLC> && !(ip.src==<HMI>)[/]                  quien toca el PLC

[b yellow]TSHARK EN VIVO[/]  (ya tienes Wireshark -> tienes tshark)
[cyan]tshark -i eth0 -Y "modbus.func_code>=5 && modbus.func_code<=16" \\
      -T fields -e frame.time -e ip.src -e ip.dst -e modbus.func_code[/]
[cyan]tshark -i eth0 -Y "104asdu.typeid>=45 && 104asdu.typeid<=51" \\
      -T fields -e frame.time -e ip.src -e ip.dst -e 104asdu.typeid[/]

[dim]Baseline SIEMPRE primero: Statistics > Conversations / Endpoints.[/]"""

ATTACK_ROWS = [
    ("Escaneo / recon",
     "SYN a puertos OT o FC43 / C_IC(100) para enumerar",
     "Marca el origen. Es el preludio. Vigilalo"),
    ("Escritura Modbus",
     "Origen != HMI envia FC 5/6/15/16",
     "Aisla origen por ACL. NO reinicies el PLC"),
    ("Comando IEC-104",
     "C_SC(45)/C_DC(46)/C_SE = control de subestacion",
     "Origen ilegitimo = Industroyer. No cortes el proceso"),
    ("Silenciar telemetria",
     "STOPDT inesperado / supresion de alarmas",
     "Correlaciona: acompana a un comando. No te fies de 'todo verde'"),
    ("S7 / stop de CPU",
     "job S7 stop o download de bloque",
     "Escritura de logica = sabotaje. Aisla; preserva evidencia"),
    ("Acceso inicial (IT)",
     "Creds en claro o RDP a estacion de ingenieria",
     "Detecta el pivote IT->OT en la IDMZ. Corta la sesion"),
]

ATTCK = """[b yellow]MITRE ATT&CK for ICS · 12 tacticas[/]
[cyan]01 Initial Access[/]      exploit public-facing app · remote services · spearphishing
[cyan]02 Execution[/]           modify controller tasking · scripting · native API
[cyan]03 Persistence[/]         valid accounts · modify program/firmware · project file
[cyan]04 Priv Escalation[/]     exploitation for priv-esc · hooking
[cyan]05 Evasion[/]             spoof reporting msg · change operating mode · rootkit
[cyan]06 Discovery[/]           network sniffing · remote system discovery
[cyan]07 Lateral Movement[/]    valid/default creds · program download · remote services
[cyan]08 Collection[/]          point & tag id · program upload · I/O image · MITM
[cyan]09 Command & Control[/]   commonly used port · standard app-layer protocol
[cyan]10 Inhibit Response[/]    block reporting/command msg · alarm suppression · DoS
[cyan]11 Impair Process Ctrl[/] unauthorized command msg · modify parameter · brute force I/O
[cyan]12 Impact[/]              loss of availability/control/view · manipulation · loss of safety

[dim]Di la tactica en voz alta al equipo cuando detectes algo. Es el idioma comun.[/]"""

RESPONSE = """[b green]SI[/]                                    [b red]NO[/]
aislar el ORIGEN del atacante (ACL)      reiniciar/apagar el PLC 'por si acaso'
cortar su sesion / conexion              desconectar la red de control entera
documentar con hora cada evento          revertir consignas tu solo sin operacion
avisar a operacion antes de tocar        escanear el PLC en pleno incidente
preservar la captura como evidencia      fiarte de que 'no hay alarmas'

[b yellow]PRIMEROS 30 MINUTOS[/]
[cyan]1[/] arranca la captura en Wireshark (graba todo)
[cyan]2[/] baseline: Statistics > Conversations / Endpoints
[cyan]3[/] localiza OT: filtra tcp.port==502||2404||102
[cyan]4[/] identifica el HMI legitimo (el que LEE el PLC)
[cyan]5[/] regla: otro origen que ESCRIBE al PLC = alerta
[cyan]6[/] lanza el Monitor de esta TUI con ese HMI/PLC

[b amber]REGLA DE ORO[/]  Disponibilidad > Integridad > Confidencialidad
Detecta -> mapea ATT&CK -> documenta -> aisla el ORIGEN, no el PLC -> reporta."""

PYSCAN = """[b yellow]pyscan · inventario y sniff[/]  (tu herramienta de baseline)
[cyan]pyscan sweep 10.10.30.0/24[/]                    descubre hosts vivos + inventario
[cyan]pyscan sweep 10.10.30.0/24 --detail[/]           + tablas de puertos por host
[cyan]pyscan scan <ip> -p 502  --type modbus --max-rate 5[/]   id Modbus (suave)
[cyan]pyscan scan <ip> -p 2404 --type iec104[/]        id IEC-104 (liveness)
[cyan]pyscan scan <ip> -p 102  --type s7comm[/]        id S7comm
[cyan]pyscan sniff capture.pcap --tui[/]               revisa una captura
[cyan]sudo pyscan sniff --live --iface eth0 --tui[/]   sniff en vivo
[dim]OT id es read-only y para simuladores; en gear real el escaneo PUEDE ser el incidente.[/]

[b yellow]nmap SEGURO[/]  (solo inventario, nunca en pleno ataque)
[cyan]nmap -sn 10.10.30.0/24[/]                         solo hosts vivos
[cyan]nmap -sT -p 502,2404,102,44818,20000,47808 -T2 --scan-delay 1s --max-rate 50 <cidr>[/]
[b red]PROHIBIDO en un PLC:[/] -A · -sV intenso · -O · -T4/-T5 · scripts NSE  (lo cuelgan)

[b yellow]lab local para practicar YA[/]
[cyan]python3 otsim.py[/]              genera capture.pcap con el ataque dentro
[cyan]python3 tools/modbus_sim.py[/]   (de pyscan) RTU Modbus falsa en 127.0.0.1:5020"""


class OTCommand(App):
    TITLE = "OT COMMAND"
    SUB_TITLE = "Blue Team · Cyber Range OT"
    BINDINGS = [("q", "quit", "Salir")]
    CSS = """
    Screen { background: $surface; }
    #bar { height: auto; padding: 1 1 0 1; }
    #bar Input { width: 1fr; margin-right: 1; }
    #btns { height: auto; padding: 0 1 1 1; }
    #btns Button { margin-right: 1; }
    #alerts { height: 1fr; border: round $panel; background: $boost; padding: 0 1; }
    #stats { height: 1; color: $text-muted; padding: 0 1; }
    .ref { padding: 1 2; }
    #tlrow { height: auto; padding: 1 1 0 1; }
    #note { width: 1fr; margin-right: 1; }
    #tl { height: 1fr; }
    DataTable { height: 1fr; }
    """

    def __init__(self):
        super().__init__()
        self.detector = None
        self.sniffer = None
        self.events = []   # (hora, tipo, detalle) para exportar

    # ---------- layout ----------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="tab-mon"):
            with TabPane("● Monitor", id="tab-mon"):
                with Horizontal(id="bar"):
                    yield Input(value="10.10.30.10", id="hmi", placeholder="IP HMI legitimo")
                    yield Input(value="10.10.30.21,10.10.40.7", id="plcs", placeholder="IPs PLC/RTU")
                    yield Input(value="eth0", id="iface", placeholder="interfaz")
                with Horizontal(id="btns"):
                    yield Button("▶ Vivo (sudo)", id="live", variant="success")
                    yield Button("■ Parar", id="stop", variant="error")
                    yield Button("⟳ Replay pcap", id="replay", variant="primary")
                    yield Button("Limpiar", id="clear")
                yield RichLog(id="alerts", markup=True, highlight=False, wrap=True)
                yield Static("motor detenido", id="stats")
            with TabPane("⏱ Timeline", id="tab-tl"):
                with Horizontal(id="tlrow"):
                    yield Input(id="note", placeholder="Anota lo que observas...")
                    yield Button("+ Evento (UTC)", id="addnote", variant="primary")
                    yield Button("⤓ Exportar informe", id="export", variant="success")
                yield DataTable(id="tl")
            with TabPane("⧉ Filtros", id="tab-flt"):
                with Horizontal(id="btns"):
                    yield Button("Copiar: escrituras Modbus", id="cp_mb")
                    yield Button("Copiar: comandos IEC-104", id="cp_iec")
                with VerticalScroll():
                    yield Static(FILTERS, classes="ref")
            with TabPane("⚑ Ataques", id="tab-atk"):
                yield DataTable(id="atk")
            with TabPane("◆ ATT&CK", id="tab-attck"):
                with VerticalScroll():
                    yield Static(ATTCK, classes="ref")
            with TabPane("✚ Respuesta", id="tab-resp"):
                with VerticalScroll():
                    yield Static(RESPONSE, classes="ref")
            with TabPane("⌘ pyscan/cmd", id="tab-cmd"):
                with VerticalScroll():
                    yield Static(PYSCAN, classes="ref")
        yield Footer()

    def on_mount(self):
        tl = self.query_one("#tl", DataTable)
        tl.add_columns("Hora UTC", "Tipo", "Detalle")
        tl.zebra_stripes = True
        atk = self.query_one("#atk", DataTable)
        atk.add_columns("Ataque", "Como se ve", "Accion")
        for r in ATTACK_ROWS:
            atk.add_row(*r)
        atk.zebra_stripes = True

    # ---------- helpers ----------
    def alog(self, msg):
        self.query_one("#alerts", RichLog).write(msg)

    def set_stats(self, txt):
        self.query_one("#stats", Static).update(txt)

    def emit_alert(self, a):
        col = SEV_COLOR.get(a["sev"], "cyan")
        self.alog(f"[{col} b][{a['sev']}][/] [b]{a['src']:>15}[/] → {a['dst']:<15} [cyan]{a['proto']}[/]  {a['what']}")
        self.alog(f"        [dim]ATT&CK:[/] {a['attack']}   [green]›[/] {a['action']}")
        self.add_event(a["sev"], f"{a['proto']} {a['src']}→{a['dst']} · {a['what']}")
        d = self.detector
        if d:
            self.set_stats(f"● motor activo · {d.packets} paquetes · {d.alerts} alertas · "
                           f"origenes hostiles: {', '.join(sorted(d.seen_src)) or '-'}")

    def add_event(self, tipo, detalle):
        h = utcnow()
        self.events.append((h, tipo, detalle))
        self.query_one("#tl", DataTable).add_row(h, tipo, detalle)

    def _new_detector(self):
        hmi = self.query_one("#hmi", Input).value.split(",")
        plcs = self.query_one("#plcs", Input).value.split(",")
        self.detector = Detector(hmi, plcs)
        return self.detector

    # ---------- botones ----------
    @on(Button.Pressed, "#live")
    def _live(self):
        if self.sniffer:
            self.alog("[yellow]ya hay una captura en marcha[/]")
            return
        iface = self.query_one("#iface", Input).value.strip()
        d = self._new_detector()
        try:
            from scapy.all import AsyncSniffer
            def cb(pkt):
                for a in d.feed(pkt):
                    self.call_from_thread(self.emit_alert, a)
            self.sniffer = AsyncSniffer(iface=iface, store=False,
                filter="tcp port 502 or tcp port 2404 or tcp port 102", prn=cb)
            self.sniffer.start()
            self.alog(f"[green]● escuchando en {iface}[/] · HMI={','.join(d.hmi)} · PLC={','.join(d.plcs)}")
            self.set_stats("● motor activo · esperando trafico...")
        except Exception as e:
            self.sniffer = None
            self.alog(f"[red]no se pudo abrir {iface}: {e}[/]")
            self.alog("[dim]la captura en vivo necesita root: cierra y ejecuta  sudo python3 ot_command.py[/]")

    @on(Button.Pressed, "#stop")
    def _stop(self):
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None
            self.alog("[yellow]■ captura detenida[/]")
            self.set_stats("motor detenido")
        else:
            self.alog("[dim]no hay captura en marcha[/]")

    @on(Button.Pressed, "#replay")
    def _replay_btn(self):
        self._new_detector()
        self.alog("[cyan]⟳ replay de capture.pcap ...[/]")
        self._replay()

    @work(thread=True, exclusive=True)
    def _replay(self):
        import time
        try:
            for a in self.detector.from_pcap("capture.pcap"):
                self.call_from_thread(self.emit_alert, a)
                time.sleep(0.25)
            self.call_from_thread(self.alog, "[green]replay completo[/]")
        except FileNotFoundError:
            self.call_from_thread(self.alog, "[red]no encuentro capture.pcap · genera con: python3 otsim.py[/]")
        except Exception as e:
            self.call_from_thread(self.alog, f"[red]error en replay: {e}[/]")

    @on(Button.Pressed, "#clear")
    def _clear(self):
        self.query_one("#alerts", RichLog).clear()

    @on(Button.Pressed, "#addnote")
    def _addnote(self):
        inp = self.query_one("#note", Input)
        if inp.value.strip():
            self.add_event("NOTA", inp.value.strip())
            inp.value = ""

    @on(Button.Pressed, "#cp_mb")
    def _cp_mb(self):
        self._copy("modbus.func_code>=5 && modbus.func_code<=16")

    @on(Button.Pressed, "#cp_iec")
    def _cp_iec(self):
        self._copy("104asdu.typeid>=45 && 104asdu.typeid<=51")

    def _copy(self, text):
        try:
            self.copy_to_clipboard(text)
            self.notify(f"copiado: {text}", timeout=3)
        except Exception:
            self.notify(f"filtro: {text}", timeout=4)

    @on(Button.Pressed, "#export")
    def _export(self):
        path = self._write_report()
        self.notify(f"informe guardado: {path}", timeout=5)
        self.add_event("INFORME", f"exportado -> {path}")

    def _write_report(self):
        d = self.detector
        iocs_src = ", ".join(sorted(d.seen_src)) if d and d.seen_src else "-"
        iocs_fc = ", ".join(sorted(d.seen_fc)) if d and d.seen_fc else "-"
        ts = datetime.now(timezone.utc)
        fname = f"informe_{ts.strftime('%Y%m%d_%H%M%S')}.md"
        lines = [
            f"# INC-{ts.strftime('%Y%m%d')}-01 · Incidente OT",
            f"Generado: {ts.strftime('%Y-%m-%d %H:%M:%S')} UTC",
            "",
            "## 1 · Resumen ejecutivo",
            "_[completar: que paso, ventana temporal, estado]_",
            "",
            "## 2 · Indicadores (IOC)",
            f"- Origen(es) hostil(es): `{iocs_src}`",
            f"- Funciones / TypeIDs vistos: `{iocs_fc}`",
            "- Puertos OT: 502 (Modbus) · 2404 (IEC-104) · 102 (S7)",
            "",
            "## 3 · Linea temporal (UTC)",
        ]
        if self.events:
            lines += [f"- **{h}** · {t} · {d_}" for (h, t, d_) in self.events]
        else:
            lines.append("_(sin eventos registrados)_")
        lines += [
            "",
            "## 4 · Mapeo ATT&CK for ICS",
            "Discovery → Collection → Impair Process Control (Unauthorized Command Message) → Impact.",
            "",
            "## 5 · Contencion y recomendaciones",
            "- Aislado el origen por ACL en la IDMZ (no el PLC).",
            "- Reposicion de consignas/interruptor coordinada con operacion.",
            "- Lista blanca de origenes hacia el PLC; alerta IDS sobre escrituras desde origen != HMI.",
        ]
        with open(fname, "w") as f:
            f.write("\n".join(lines) + "\n")
        return fname


if __name__ == "__main__":
    OTCommand().run()
