# Docker + centro de mando por menú

Todo el ejercicio desde un solo comando, sin ejecutar cosas una por una.

## Dónde va cada archivo (en la raíz del repo `pyscan/`)

```
pyscan/
├── docker/
│   └── Dockerfile.otkit      ← NUEVO  (imagen todo-en-uno)
├── docker-compose.yml        ← NUEVO
├── otkit.sh                  ← NUEVO  (el menú)
├── Makefile                  ← REEMPLAZA el tuyo (conserva tus targets + añade Docker)
├── DOCKER.md                 ← NUEVO  (esta guía)
├── README.md                 ← debe existir (lo usa pyproject/Dockerfile) *
├── pyproject.toml
├── src/pyscan/…
├── otkit/                    ← tu kit Blue Team (ya está)
└── tools/modbus_sim.py
```

\* Si al construir ves `readme file does not exist`, es que falta el README de la raíz. Arréglalo en 1 línea:
```bash
[ -f README.md ] || printf '# pyscan\n\nHexagonal port & OT-protocol scanner + Blue Team kit.\n' > README.md
```

## Requisitos

- Docker con Compose v2 (`docker compose version`).
- **Linux** para la captura en vivo: el compose usa `network_mode: host` para ver la NIC real. En tu Acer Nitro con Ubuntu es justo lo que quieres.

## El único comando que necesitas

```bash
chmod +x otkit.sh
./otkit.sh            # o:  make menu
```

Te sale el menú. La **primera vez pulsa `b`** para construir la imagen (2-3 min). Después:

```
 b) Construir / actualizar la imagen Docker
 1) TUI centro de mando   (EN VIVO: sniff real de la NIC)
 2) TUI centro de mando   (práctica: dentro pulsa Replay pcap)
 3) Generar captura de ejemplo (otsim -> capture.pcap)
 4) Watch CLI en vivo (mini-IDS sin TUI)
 5) pyscan sweep   (inventario de la red)
 6) pyscan scan    (identificar un host / PLC)
 7) pyscan sniff --live --tui
 8) Ejecutar tests
 9) Shell dentro del contenedor
 0) Salir
```

`capture.pcap` y los `informe_*.md` que exportes desde la TUI aparecen en tu carpeta `otkit/` del host (va montada como volumen).

## Si prefieres `make` en vez del menú

```bash
make build                      # construir imagen
make tui                        # abrir el centro de mando
make sim                        # generar capture.pcap
make watch IFACE=eth0 HMI=10.0.0.5 PLC=10.0.0.21,10.0.0.7
make sweep CIDR=10.10.30.0/24
make scan  HOST=10.10.30.21 PORT=502 TYPE=modbus
make sniff IFACE=eth0
make dtest                      # tests dentro del contenedor
make shell
```

## Fallback sin menú ni make (docker directo)

```bash
docker build -f docker/Dockerfile.otkit -t pyscan-otkit .
# TUI en vivo (host net + permisos de captura):
docker compose run --rm otkit python ot_command.py
# o pyscan dentro de la misma imagen:
docker compose run --rm otkit pyscan sweep 10.10.30.0/24
```

## Qué lleva la imagen

pyscan instalado con extras `syn` (scapy), `tui` (textual) y `lab` (pymodbus), más **tshark** y **nmap**.
Es decir: en el mismo contenedor tienes pyscan, el kit otkit (TUI/otwatch/otsim), Wireshark-CLI y nmap.
`PYTHONPATH=/app/otkit` para que `otcore` se importe suelto, igual que en local.

## Nota de seguridad OT

El contenedor tiene `NET_RAW`/`NET_ADMIN` para poder capturar, no para atacar. Mantén la regla:
**nunca escanees fuerte un PLC** (`-A`, `-sV` intenso, `-T4/5`, NSE). El menú ya lanza `pyscan scan` con `--max-rate 5`.
