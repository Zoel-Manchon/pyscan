# OTKIT — centro de mando Blue Team OT (para mañana)

Kit express, probado y funcionando. Piezas:

| Fichero | Qué es |
|---|---|
| **ot_command.py** | **La TUI: centro de mando.** Monitor en vivo + timeline + informe + toda la referencia con botones. |
| otcore.py | Motor de detección compartido (Modbus/IEC-104/S7comm). No se ejecuta solo. |
| otwatch.py | Mini-IDS en línea de comandos (mismo motor, para terminal pura). |
| otsim.py | Genera `capture.pcap` con un ataque dentro, para practicar. |
| capture.pcap | Captura de ejemplo ya generada (recon → escrituras → comando IEC-104 → STOPDT). |

## Instalación (una vez)

```bash
pip install textual scapy --break-system-packages
# tshark ya lo tienes con Wireshark
```

## LA TUI — tu centro de mando

```bash
python3 ot_command.py            # sin captura en vivo (referencia + replay)
sudo python3 ot_command.py       # con captura en vivo (necesita root)
```

Pestañas:
- **● Monitor** — pon el HMI legítimo y las IPs de PLC/RTU, y pulsa **▶ Vivo** para escuchar
  la interfaz, o **⟳ Replay pcap** para practicar con `capture.pcap`. Cada escritura/comando OT
  salta como alerta con severidad, mapeo ATT&CK y acción recomendada.
- **⏱ Timeline** — las alertas se registran solas con hora UTC. Añade tus notas con **+ Evento**
  y pulsa **⤓ Exportar informe** para volcar un `informe_*.md` listo (IOCs + línea temporal + plantilla).
- **⧉ Filtros** — filtros de Wireshark y tshark; botones para copiar los dos más usados.
- **⚑ Ataques / ◆ ATT&CK / ✚ Respuesta / ⌘ pyscan/cmd** — toda la referencia a mano.

Tecla **q** para salir.

## Práctica de esta noche (10 min)

```bash
python3 otsim.py                 # crea capture.pcap
python3 ot_command.py            # abre la TUI -> pestaña Monitor -> ⟳ Replay pcap
```
Mira cómo caza el patrón **talker nuevo → recon → escritura/comando**. Repite hasta reconocerlo solo.

## Mañana, en el ejercicio

1. **Wireshark encendido** grabando desde el minuto cero.
2. **Baseline**: `Statistics > Conversations` y `Endpoints`. Apunta quién habla con quién y cuál es el HMI.
3. Abre la TUI (`sudo python3 ot_command.py`), mete el HMI y los PLC reales, **▶ Vivo**.
4. Registra hallazgos en **Timeline** y exporta el informe al final.

### Fallback sin TUI (terminal pura)
```bash
python3 otwatch.py capture.pcap                       # practica
sudo python3 otwatch.py --iface eth0 --hmi <IP> --plc <IP>,<IP>   # en vivo
```

## pyscan — tu baseline (complementa, no sustituye)

pyscan hace el **inventario** (read-only); otwatch/otcore hace la **detección de sabotaje**. Juntos cubren todo.
```bash
pyscan sweep 10.10.30.0/24 --detail                   # qué hay en la red
pyscan scan <ip> -p 502 --type modbus --max-rate 5    # identifica un PLC (suave)
sudo pyscan sniff --live --iface eth0 --tui           # sniff en vivo
```
> OT id es read-only y para simuladores. **Nunca escanees fuerte un PLC** (`-A`, `-sV` intenso,
> `-O`, `-T4/5`, NSE): puede colgarlo y causar el mismo apagón que busca el atacante.

## Regla de oro

**Disponibilidad > Integridad > Confidencialidad.** Detecta → documenta con hora → **aísla el ORIGEN, no el PLC** → reporta.
