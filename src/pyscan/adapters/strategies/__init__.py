"""Importing this package registers every built-in scan strategy.

Each concrete strategy module self-registers on import via @register(...), so
adding a new technique is: write the file, add one import line here.
"""

from pyscan.adapters.strategies import (
    iec104,  # noqa: F401  (self-registers)
    modbus,  # noqa: F401  (self-registers)
    s7comm,  # noqa: F401  (self-registers)
    tcp_connect,  # noqa: F401  (self-registers)
)
from pyscan.adapters.strategies.registry import available, get_strategy, register

__all__ = ["available", "get_strategy", "register"]
