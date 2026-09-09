# Running pyscan in Docker

Two images, for two different jobs.

| Image | Built from | What it is for |
| --- | --- | --- |
| `pyscan` | `Dockerfile` | The scanner as a command. Small, no system packages. |
| `pyscan-otkit` | `docker/Dockerfile.otkit` | The full exercise kit: pyscan with every extra, plus tshark and nmap. |

---

## The scanner, as a command

```bash
docker build -t pyscan .
docker run --rm pyscan scan scanme.nmap.org -p 22,80,443
docker run --rm pyscan sweep 192.168.1.0/24 --max-rate 5
```

The image *is* the command — `pyscan` is the entrypoint, so anything you would
type after `pyscan` goes after the image name. To read a capture from your
machine, mount the directory it lives in:

```bash
docker run --rm -v "$PWD:/data" -w /data pyscan sniff capture.pcapng
docker run --rm -v "$PWD:/data" -w /data pyscan monitor capture.pcapng --hmi 10.10.30.10
```

This is deliberately not orchestrated. There is no long-running service to
scale here, which is the problem Kubernetes exists to solve.

---

## The exercise kit

One menu drives everything:

```bash
./otkit.sh          # or: make menu
```

```
  b) Build / refresh the Docker image
  1) OT command centre, LIVE   (real capture off the NIC)
  2) OT command centre, replay (practise against capture.pcap)
  3) Generate a practice capture with an attack inside it
  4) Mini-IDS in the terminal, live (no TUI)
  5) pyscan sweep   (network inventory, throttled)
  6) pyscan scan    (identify one host / PLC)
  7) pyscan sniff --live --tui
  8) Run the test suite
  9) Shell inside the container
```

Press `b` once to build, then work from the menu. Captures and the incident
reports you export land in `./otkit/` on your host, because that directory is
mounted as a volume — they outlive the container.

### The same thing without the menu

```bash
make build                                   # build the image
make sim                                     # generate capture.pcap
make tui                                     # OT command centre
make watch IFACE=eth0 HMI=10.10.30.10 PLC=10.10.30.21
make sweep CIDR=10.10.30.0/24
make scan HOST=10.10.30.21 PORT=502 TYPE=modbus
make dtest                                   # run the test suite in the container
```

---

## Why the compose file looks like that

```yaml
network_mode: host
cap_add: [NET_RAW, NET_ADMIN]
```

* `network_mode: host` lets the container see the real interface. Without it,
  live capture only ever sees the container's own virtual NIC. **Linux only** —
  on Docker Desktop for macOS and Windows the container runs inside a VM, so
  there is no host NIC to see. Read a capture file instead.
* `NET_RAW` / `NET_ADMIN` allow packet capture and raw-socket scanning without
  handing the container `--privileged`, which would give it far more than it
  needs.

Live capture still needs those capabilities *and* Linux. Everything else —
reading captures, replaying them through the detection engine, connect scans,
UDP scans, OT identification — works unprivileged, on any platform.

---

## Safety

OT identification is read-only by design and meant for simulators or lab
equipment you own. On live ICS gear the scan itself can be the incident. When
you must touch real equipment, throttle it: `--max-rate 5` is not politeness,
it is the safety feature.
