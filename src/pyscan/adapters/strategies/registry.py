"""Scan-strategy registry.

A decorator registers each scan technique under a name. Adding a new scan
type later (SYN, FIN, UDP, ...) is a single new file ending in:

    @register("syn")
    class SynScan: ...

No edits to the engine, the CLI, or anything else. That is the extensibility
payoff of keeping strategies behind a registry.
"""

from __future__ import annotations

from collections.abc import Callable

from pyscan.domain.ports import ScanStrategy

_REGISTRY: dict[str, type] = {}


def register(name: str) -> Callable[[type], type]:
    def decorator(cls: type) -> type:
        cls.name = name  # type: ignore[attr-defined]
        _REGISTRY[name] = cls
        return cls

    return decorator


def get_strategy(name: str, **options) -> ScanStrategy:
    try:
        cls = _REGISTRY[name]
    except KeyError:
        raise KeyError(
            f"Unknown scan strategy {name!r}. Available: {', '.join(available())}"
        ) from None
    return cls(**options)


def available() -> list[str]:
    return sorted(_REGISTRY)
