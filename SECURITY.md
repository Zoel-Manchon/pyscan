# Security policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/Zoel-Manchon/pyscan/security/advisories/new)
rather than opening a public issue. I will acknowledge within a few days and
credit you in the fix unless you would rather stay anonymous.

## What this project does to itself

A scanner that never audits its own code is asking for trust it has not earned.
Every push and pull request runs:

| Gate | Tool | What it catches |
| --- | --- | --- |
| Lint | ruff | style, unused code, common bug patterns |
| Types | mypy `--strict` | contract violations across the whole hexagon |
| Tests | pytest, coverage gate at 85% | behaviour, on Linux, macOS and Windows |
| Static analysis | bandit | insecure API use in the source |
| Semantic analysis | CodeQL (`security-and-quality`) | injection, path traversal, taint flow |
| Dependencies | pip-audit | known CVEs in the dependency tree |
| Updates | Dependabot | pip, GitHub Actions and Docker base image |

## Scope of the tool itself

pyscan is a scanner and a traffic analyser. Used against systems you do not own
or have written authorisation to test, it may well be illegal where you are.
That is on the operator, not on the tool.

The OT features carry a sharper edge, so they are constrained by design:

* **Identification is read-only.** Modbus asks for the device-ID object,
  IEC-104 sends a TESTFR keepalive, S7comm reads an SZL record. The code to
  write a coil, issue a control command or stop a CPU does not exist in this
  repository, and will not be added.
* **The detection engine only ever reads.** It parses captured frames. It never
  injects, resets a connection, or answers on the wire.
* **`--max-rate` exists for a reason.** Fragile ICS equipment can fall over
  under an ordinary scan. Against real plant, throttle it — and prefer a
  simulator.

On live ICS equipment, the scan itself can be the incident.
