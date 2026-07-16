# Installation

Status: supported on Python 3.11 and 3.12.

Create an isolated environment, install the wheel or local candidate with `python -m pip install .`, then verify `mnemoir --help` and `mnemoir --version`. The base install has no Hermes dependency. Use the `hermes` extra only for the optional reference adapter.

Set `MNEMOIR_DB` to an operator-owned SQLite path. Uninstalling the package does not delete that database; remove it only after an explicit backup/retention decision.
