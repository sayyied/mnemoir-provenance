# Local deployment

Run in a dedicated Python environment with an operator-owned SQLite path and restrictive filesystem permissions. The base library starts no daemon or listener. `mnemoir ui` binds only to loopback. Service commands manage only the documented local runtime and do not install operating-system persistence.

Back up the database and private writeback transaction root separately.
