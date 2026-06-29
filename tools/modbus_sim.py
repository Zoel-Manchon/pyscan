#!/usr/bin/env python3
"""Modbus/TCP simulator — a fake energy-substation RTU.

A practice target, not part of the scanner. It does two jobs:
  1. Gives `pyscan scan <host> -p <port> --type modbus` a real device to
     identify (vendor / product / firmware via Read Device ID, FC 43/14).
  2. Serves register reads (voltage / current / frequency / breaker state) so
     you can poll it, capture the traffic, and analyse the Modbus exchange in
     Wireshark — the core Blue-Team skill for the CIUDEN range.

Run (no root needed on port 5020):
    python3 tools/modbus_sim.py
    sudo python3 tools/modbus_sim.py --port 502    # privileged port needs root

Then, in another terminal:
    pyscan scan 127.0.0.1 -p 5020 --type modbus            # identify the "PLC"
    sudo .venv/bin/pyscan sniff --live --iface lo --tui     # watch its traffic

Register map (holding & input registers):
    0  voltage L1 (V)      3  current L1 (A)      6  frequency (Hz x100)
    1  voltage L2 (V)      4  current L2 (A)      7  active power (kW)
    2  voltage L3 (V)      5  current L3 (A)
Coils (FC 1):  0 breaker-1 closed   1 breaker-2 closed
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import warnings

warnings.filterwarnings("ignore")
logging.getLogger("pymodbus").setLevel(logging.ERROR)

from pymodbus import ModbusDeviceIdentification  # noqa: E402
from pymodbus.datastore import (  # noqa: E402
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.server import StartAsyncTcpServer  # noqa: E402

# Substation readings.  V x3, A x3, frequency (x100 -> 50.00 Hz), active power kW
_HOLDING = [230, 231, 229, 12, 13, 11, 5000, 75]
_COILS = [1, 1, 0, 0, 0, 0, 0, 0]  # two breakers closed


def build_context() -> ModbusServerContext:
    device = ModbusDeviceContext(
        di=ModbusSequentialDataBlock(1, [0] * 16),
        co=ModbusSequentialDataBlock(1, _COILS),
        hr=ModbusSequentialDataBlock(1, _HOLDING + [0] * 8),
        ir=ModbusSequentialDataBlock(1, _HOLDING + [0] * 8),
    )
    return ModbusServerContext(devices=device, single=True)


def build_identity() -> ModbusDeviceIdentification:
    ident = ModbusDeviceIdentification()
    ident.VendorName = "pyscan-lab"
    ident.ProductCode = "VPLC-01"
    ident.VendorUrl = "https://github.com/Zoel-Manchon/pyscan"
    ident.ProductName = "Virtual Substation RTU"
    ident.ModelName = "VS-RTU 868"
    ident.MajorMinorRevision = "1.4.2"
    return ident


async def main() -> None:
    ap = argparse.ArgumentParser(description="Modbus/TCP substation-RTU simulator.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5020, help="default 5020 (502 needs root)")
    args = ap.parse_args()

    print("┌─ Modbus/TCP simulator — Virtual Substation RTU")
    print(f"│  listening on {args.host}:{args.port}")
    print("│  identity: pyscan-lab / Virtual Substation RTU / fw 1.4.2")
    print(f"│  try:  pyscan scan {args.host} -p {args.port} --type modbus")
    print("└─ Ctrl-C to stop\n")

    await StartAsyncTcpServer(
        context=build_context(), identity=build_identity(), address=(args.host, args.port)
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nsimulator stopped.")
