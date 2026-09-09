# otkit — the OT exercise workspace

This directory is a **workspace**, not a code kit. It holds the captures you
record and the incident reports you export during an exercise, and it is the
directory Docker mounts from your host so both survive the container.

The OT tooling itself now lives inside pyscan, where it shares the scanner's
protocol codecs instead of re-implementing them:

| What you used to run here | What to run now |
| --- | --- |
| `python otsim.py` | `pyscan lab capture.pcap` |
| `python otwatch.py capture.pcap` | `pyscan monitor capture.pcap` |
| `sudo python otwatch.py --iface eth0` | `sudo pyscan monitor --live --iface eth0` |
| `python ot_command.py` | `pyscan monitor --tui` |
| `sudo python ot_command.py` | `sudo pyscan monitor --live --iface eth0 --tui` |

## A ten-minute drill

```bash
pyscan lab capture.pcap                      # a capture with an attack inside
pyscan monitor capture.pcap --hmi 10.10.30.10 --plc 10.10.30.21,10.10.40.7
pyscan monitor capture.pcap --tui            # same thing, command-centre view
```

Watch for the shape: **new talker → reconnaissance → write / control command.**
That sequence is most of the published ICS intrusions, and recognising it
without thinking is the entire skill.

## During a real exercise

1. Start a full packet capture before anything else. It is your evidence.
2. Build a baseline: who talks to whom, and which station is the HMI.
3. `sudo pyscan monitor --live --iface eth0 --tui`, with the real HMI and PLC
   addresses in the Monitor tab.
4. Record findings in the Timeline tab, then export the report before you leave.

Availability > Integrity > Confidentiality. Isolate the **source**, never the PLC.
