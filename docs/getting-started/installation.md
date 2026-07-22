# Installation

Status: Python 3.11 and 3.12 are supported. Normal users start from PyPI: `python -m venv .venv`, activate it, then run `python -m pip install mnemoir-provenance`, `python -m pip check`, `python -c "import mnemoir_provenance; print(mnemoir_provenance.__version__)"`, and `mnemoir --version`. The identity matrix is distribution `mnemoir-provenance`, command `mnemoir`, import `mnemoir_provenance`, and Hermes provider `mnemoir_provenance`; do not use `pip install mnemoir`.

A first installation uses `python -m pip install mnemoir-provenance`. To replace an older installed version with the newest available release, use `python -m pip install --upgrade mnemoir-provenance`. For an exact reproducible install, pin the release with `python -m pip install 'mnemoir-provenance==0.2.1'`; `--upgrade` is unnecessary with an exact pin.

The base install is standalone and has no Hermes dependency. A development clone is a separate contributor path: clone the repository and install `-e '.[test]'`. For a fresh shared Hermes environment install `mnemoir-provenance[hermes]`; for existing Hermes, invoke `-m pip` with the exact Python interpreter that owns `hermes`. Set `MNEMOIR_DB` to an operator-owned SQLite path. Uninstalling the package or disabling a plugin does not delete that database; remove it only after an explicit backup/retention decision.
