"""Textual TUI: the OT command centre.

A blue-team console for an ICS exercise — live detection, an evidence timeline,
a one-keystroke incident report, and the reference material you actually need
while something is happening.

It is an adapter and nothing more. Every alert it renders comes from
`domain.ot_detect` via `MonitorService`; every frame comes from the same
`read_pcap` / `live_capture` pair the sniffer uses. Replacing this UI would not
change a single detection rule, which is the point.

textual is an optional dependency (`pip install pyscan[tui]`); this module is
imported only when the TUI path runs.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    RichLog,
    Static,
    TabbedContent,
    TabPane,
)
from textual.worker import get_current_worker

from pyscan.adapters.output.incident_report import write_report
from pyscan.application.monitor_service import MonitorService
from pyscan.domain.ot_detect import Alert, Baseline, Detector, Severity

Frame = tuple[float, int, bytes]
FrameSource = Iterator[Frame | None]

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.INFO: "cyan",
}

FILTERS = """[b yellow]WIRESHARK DISPLAY FILTERS[/]
[cyan]modbus.func_code >= 5 && modbus.func_code <= 16[/]   Modbus writes
[cyan]104asdu.typeid >= 45 && 104asdu.typeid <= 51[/]      IEC-104 control commands
[cyan]dnp3.al.func == 4 || dnp3.al.func == 5[/]            DNP3 control
[cyan]s7comm.param.func[/]                                 S7 functions
[cyan]tcp.flags.syn==1 && tcp.flags.ack==0[/]              scanning (SYN)
[cyan]telnet || ftp || http.authorization[/]               cleartext credentials
[cyan]ip.dst==<PLC> && !(ip.src==<HMI>)[/]                 who is touching the PLC

[b yellow]TSHARK, LIVE[/]
[cyan]tshark -i eth0 -Y "modbus.func_code>=5 && modbus.func_code<=16" \\
      -T fields -e frame.time -e ip.src -e ip.dst -e modbus.func_code[/]
[cyan]tshark -i eth0 -Y "104asdu.typeid>=45 && 104asdu.typeid<=51" \\
      -T fields -e frame.time -e ip.src -e ip.dst -e 104asdu.typeid[/]

[dim]Baseline first, always: Statistics > Conversations, then Endpoints.[/]"""

ATTACK_ROWS = [
    ("Scanning / recon",
     "SYN to OT ports, or FC43 / C_IC(100) enumeration",
     "Mark the source. This is the prelude - watch it"),
    ("Modbus write",
     "A source that is not the HMI sends FC 5/6/15/16",
     "Isolate the source by ACL. Do NOT reboot the PLC"),
    ("IEC-104 command",
     "C_SC(45) / C_DC(46) / C_SE - substation control",
     "Illegitimate source = Industroyer pattern. Do not cut the process"),
    ("Silencing telemetry",
     "Unexpected STOPDT, or alarm suppression",
     "It accompanies a command. Never trust an all-green HMI"),
    ("S7 program / CPU stop",
     "S7 job: PLC stop, or block download",
     "Logic is being rewritten. Isolate; preserve evidence"),
    ("IT-to-OT pivot",
     "Cleartext credentials or RDP to an engineering station",
     "Catch the pivot at the IDMZ. Cut the session"),
]

ATTCK = """[b yellow]MITRE ATT&CK for ICS - the 12 tactics[/]
[cyan]01 Initial Access[/]      exploit public-facing app - remote services - spearphishing
[cyan]02 Execution[/]           modify controller tasking - scripting - native API
[cyan]03 Persistence[/]         valid accounts - modify program/firmware - project file
[cyan]04 Priv Escalation[/]     exploitation for privilege escalation - hooking
[cyan]05 Evasion[/]             spoof reporting message - change operating mode - rootkit
[cyan]06 Discovery[/]           network sniffing - remote system discovery
[cyan]07 Lateral Movement[/]    valid/default credentials - program download - remote services
[cyan]08 Collection[/]          point & tag identification - program upload - I/O image - MITM
[cyan]09 Command & Control[/]   commonly used port - standard application layer protocol
[cyan]10 Inhibit Response[/]    block reporting/command message - alarm suppression - DoS
[cyan]11 Impair Process Ctrl[/] unauthorized command message - modify parameter - brute force I/O
[cyan]12 Impact[/]              loss of availability/control/view - manipulation - loss of safety

[dim]Say the tactic out loud to the team when you spot something. It is the shared language.[/]"""

RESPONSE = """[b green]DO[/]                                     [b red]DO NOT[/]
isolate the attacker SOURCE (ACL)         reboot or power off the PLC "just in case"
cut its session / connection              disconnect the whole control network
timestamp every observation               revert setpoints alone, without operations
tell operations before you touch          scan the PLC during an active incident
preserve the capture as evidence          trust that "there are no alarms"

[b yellow]THE FIRST 30 MINUTES[/]
[cyan]1[/] start the capture and never stop it (this is your evidence)
[cyan]2[/] baseline: Statistics > Conversations / Endpoints
[cyan]3[/] find OT: filter tcp.port==502 || 2404 || 102
[cyan]4[/] identify the legitimate HMI (the station that READS the PLC)
[cyan]5[/] the rule: any other source that WRITES to the PLC is an alert
[cyan]6[/] put that HMI/PLC into the Monitor tab and start it

[b yellow]THE GOLDEN RULE[/]  Availability > Integrity > Confidentiality
Detect -> map to ATT&CK -> document -> isolate the SOURCE, not the PLC -> report."""

COMMANDS = """[b yellow]pyscan - inventory and capture[/]
[cyan]pyscan sweep 10.10.30.0/24 --max-rate 5[/]        live hosts + inventory, throttled
[cyan]pyscan sweep 10.10.30.0/24 --detail[/]            + per-host port tables
[cyan]pyscan scan <ip> -p 502  --type modbus --max-rate 5[/]  Modbus id (gentle)
[cyan]pyscan scan <ip> -p 2404 --type iec104[/]         IEC-104 liveness
[cyan]pyscan scan <ip> -p 102  --type s7comm[/]         S7comm id
[cyan]pyscan sniff capture.pcapng --tui[/]              review a capture
[cyan]sudo pyscan sniff --live --iface eth0 --tui[/]    live packet view
[cyan]sudo pyscan monitor --live --iface eth0 --tui[/]  THIS console, live
[dim]OT identification is read-only and meant for simulators. On live ICS gear the
scan can BE the incident.[/]

[b yellow]SAFE nmap[/]  (inventory only, never mid-incident)
[cyan]nmap -sn 10.10.30.0/24[/]                          live hosts only
[cyan]nmap -sT -p 502,2404,102,44818,20000,47808 -T2 --scan-delay 1s --max-rate 50 <cidr>[/]
[b red]NEVER against a PLC:[/] -A - aggressive -sV - -O - -T4/-T5 - NSE scripts

[b yellow]local lab, right now[/]
[cyan]pyscan lab capture.pcap[/]        generate a practice capture with the attack in it
[cyan]python tools/modbus_sim.py[/]     a fake Modbus RTU on 127.0.0.1:5020"""


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%H:%M:%S")


class MonitorApp(App[None]):
    TITLE = "OT COMMAND"
    SUB_TITLE = "blue team - ICS monitoring"
    BINDINGS = [("q", "quit", "Quit")]
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
    DataTable { height: 1fr; }
    """

    def __init__(
        self,
        baseline: Baseline,
        capture: Path | None = None,
        iface: str | None = None,
        source: FrameSource | None = None,
    ) -> None:
        super().__init__()
        self._baseline = baseline
        self._capture = capture
        self._iface = iface or "eth0"
        self._pending_source = source
        self._service: MonitorService | None = None
        self._timeline: list[tuple[str, str, str]] = []

    # -- layout -------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="tab-monitor"):
            with TabPane("Monitor", id="tab-monitor"):
                with Horizontal(id="bar"):
                    yield Input(
                        value=",".join(sorted(self._baseline.hmi)),
                        id="hmi",
                        placeholder="legitimate HMI address(es)",
                    )
                    yield Input(
                        value=",".join(sorted(self._baseline.plcs)),
                        id="plcs",
                        placeholder="PLC / RTU addresses (blank = protect all)",
                    )
                    yield Input(value=self._iface, id="iface", placeholder="interface")
                with Horizontal(id="btns"):
                    yield Button("Start live", id="live", variant="success")
                    yield Button("Stop", id="stop", variant="error")
                    yield Button("Replay capture", id="replay", variant="primary")
                    yield Button("Clear", id="clear")
                yield RichLog(id="alerts", markup=True, highlight=False, wrap=True)
                yield Static("engine idle", id="stats")
            with TabPane("Timeline", id="tab-timeline"):
                with Horizontal(id="tlrow"):
                    yield Input(id="note", placeholder="Record what you observe...")
                    yield Button("Add event (UTC)", id="addnote", variant="primary")
                    yield Button("Export report", id="export", variant="success")
                yield DataTable(id="timeline")
            with TabPane("Filters", id="tab-filters"), VerticalScroll():
                yield Static(FILTERS, classes="ref")
            with TabPane("Attacks", id="tab-attacks"):
                yield DataTable(id="attacks")
            with TabPane("ATT&CK", id="tab-attck"), VerticalScroll():
                yield Static(ATTCK, classes="ref")
            with TabPane("Response", id="tab-response"), VerticalScroll():
                yield Static(RESPONSE, classes="ref")
            with TabPane("Commands", id="tab-commands"), VerticalScroll():
                yield Static(COMMANDS, classes="ref")
        yield Footer()

    def on_mount(self) -> None:
        timeline = self.query_one("#timeline", DataTable)
        timeline.add_columns("UTC", "Kind", "Detail")
        timeline.zebra_stripes = True

        attacks = self.query_one("#attacks", DataTable)
        attacks.add_columns("Attack", "What it looks like", "What to do")
        for row in ATTACK_ROWS:
            attacks.add_row(*row)
        attacks.zebra_stripes = True

        if self._pending_source is not None:
            self._start(self._pending_source, "live capture")
            self._pending_source = None
        elif self._capture is not None:
            self._start_replay()

    # -- rendering ----------------------------------------------------------
    def _write(self, markup: str) -> None:
        self.query_one("#alerts", RichLog).write(markup)

    def show_alert(self, alert: Alert) -> None:
        style = _SEVERITY_STYLE.get(alert.severity, "cyan")
        self._write(
            f"[{style} b][{alert.severity.value}][/] "
            f"[b]{alert.src:>15}[/] -> {alert.dst:<15} "
            f"[cyan]{alert.protocol}[/]  {alert.summary}"
        )
        self._write(f"        [dim]ATT&CK:[/] {alert.technique}   [green]>[/] {alert.action}")
        self.add_event(alert.severity.value, f"{alert.protocol} {alert.src} -> {alert.dst}: {alert.summary}")
        self._refresh_stats()

    def _refresh_stats(self) -> None:
        if self._service is None:
            self.query_one("#stats", Static).update("engine idle")
            return
        detector = self._service.detector
        sources = ", ".join(sorted(detector.hostile_sources)) or "-"
        self.query_one("#stats", Static).update(
            f"engine running - {detector.packets} OT packets - {detector.alerts} alerts - "
            f"hostile sources: {sources}"
        )

    def add_event(self, kind: str, detail: str) -> None:
        when = _utc_now()
        self._timeline.append((when, kind, detail))
        self.query_one("#timeline", DataTable).add_row(when, kind, detail)

    # -- engine control -----------------------------------------------------
    def _build_service(self) -> MonitorService:
        baseline = Baseline.of(
            self.query_one("#hmi", Input).value,
            self.query_one("#plcs", Input).value,
        )
        self._service = MonitorService(Detector(baseline=baseline))
        return self._service

    def _start(self, source: FrameSource, label: str) -> None:
        service = self._build_service()
        baseline = service.detector.baseline
        self._write(
            f"[green]monitoring {label}[/] - HMI: {', '.join(sorted(baseline.hmi)) or 'unset'} - "
            f"protecting: {', '.join(sorted(baseline.plcs)) or 'every OT destination'}"
        )
        self.consume(source)

    @work(thread=True, exclusive=True)
    def consume(self, source: FrameSource) -> None:
        worker = get_current_worker()
        service = self._service
        if service is None:
            return
        try:
            for alert in service.run(source):
                if worker.is_cancelled:
                    break
                self.call_from_thread(self.show_alert, alert)
        except Exception as exc:  # a dead interface or a corrupt file, mid-stream
            self.call_from_thread(self._write, f"[red]capture stopped: {exc}[/]")
        else:
            self.call_from_thread(self._write, "[green]source exhausted[/]")
        self.call_from_thread(self._refresh_stats)

    @on(Button.Pressed, "#live")
    def _on_live(self) -> None:
        from pyscan.adapters.capture.live_capture import live_capture

        iface = self.query_one("#iface", Input).value.strip() or None
        try:
            source = live_capture(iface)
        except RuntimeError as exc:
            self._write(f"[red]{exc}[/]")
            return
        self._start(source, f"interface {iface or 'any'}")

    @on(Button.Pressed, "#stop")
    def _on_stop(self) -> None:
        self.workers.cancel_all()
        self._write("[yellow]capture stopped[/]")
        self._refresh_stats()

    @on(Button.Pressed, "#replay")
    def _on_replay(self) -> None:
        self._start_replay()

    def _start_replay(self) -> None:
        from pyscan.adapters.capture.pcap_reader import read_pcap

        path = self._capture or Path("capture.pcap")
        try:
            frames = list(read_pcap(path))
        except (OSError, ValueError) as exc:
            self._write(f"[red]cannot replay {path}: {exc}[/]")
            self._write("[dim]generate a practice capture with:  pyscan lab capture.pcap[/]")
            return
        self._start(iter(frames), f"replay of {path.name}")

    @on(Button.Pressed, "#clear")
    def _on_clear(self) -> None:
        self.query_one("#alerts", RichLog).clear()

    @on(Button.Pressed, "#addnote")
    def _on_add_note(self) -> None:
        field = self.query_one("#note", Input)
        if field.value.strip():
            self.add_event("NOTE", field.value.strip())
            field.value = ""

    @on(Button.Pressed, "#export")
    def _on_export(self) -> None:
        detector = self._service.detector if self._service else Detector()
        stamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        path = write_report(f"incident_{stamp}.md", detector, self._timeline)
        self.notify(f"report written: {path}", timeout=5)
        self.add_event("REPORT", f"exported -> {path}")


def run_monitor_tui(
    baseline: Baseline,
    capture: Path | None = None,
    iface: str | None = None,
    source: FrameSource | None = None,
) -> None:
    MonitorApp(baseline, capture=capture, iface=iface, source=source).run()
