"""Application layer: the OT monitoring use case.

Frames in, alerts out. The service owns no I/O of its own — it is handed any
iterator of raw frames, which is the same shape `pcap_reader.read_pcap` and
`live_capture.live_capture` both produce. So replaying a capture and watching
an interface are literally the same code path, and the one that runs during an
exercise is the one that was exercised against a file.

The decode step is `domain.packet`, the rules are `domain.ot_detect`; both are
pure. This layer only sequences them and keeps the running counters.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from pyscan.domain.ot_detect import Alert, Detector, Severity, at_least
from pyscan.domain.packet import decode

Frame = tuple[float, int, bytes]


class MonitorService:
    def __init__(self, detector: Detector, min_severity: Severity = Severity.MEDIUM) -> None:
        self._detector = detector
        self._min_severity = min_severity

    @property
    def detector(self) -> Detector:
        return self._detector

    def run(self, source: Iterable[Frame | None]) -> Iterator[Alert]:
        """Yield alerts as frames arrive.

        A None in the stream is the live capture's heartbeat — it means "no
        packet this tick, but I am still here", and it exists so a consumer
        (the TUI) can notice a quit request between packets. Passing it through
        as a yield of nothing keeps the consumer responsive without inventing a
        second control channel.
        """
        for frame in source:
            if frame is None:
                continue
            ts, linktype, raw = frame
            packet = decode(raw, linktype, ts)
            for alert in self._detector.feed(packet):
                if at_least(alert.severity, self._min_severity):
                    yield alert
