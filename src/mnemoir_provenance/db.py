"""SQLite database helpers for Mnemoir Provenance compat 01."""
from __future__ import annotations
import hashlib
from importlib import resources
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import time
SQLITE_BUSY_TIMEOUT_SECONDS = 60
SQLITE_BUSY_TIMEOUT_MS = SQLITE_BUSY_TIMEOUT_SECONDS * 1000
PACKAGE_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = resources.files('mnemoir_provenance.resources').joinpath('0001_initial_schema.sql')
DEFAULT_DB_PATH = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')) / 'mnemoir-provenance' / 'mnemoir.sqlite'

def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

def json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'))

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def stable_id(prefix: str, *parts: object) -> str:
    payload = '\x1f'.join((str(part) for part in parts))
    return f"{prefix}_{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:24]}"

def resolve_db_path(db_path: str | Path | None=None) -> Path:
    configured = db_path or os.environ.get('MNEMOIR_DB')
    return Path(configured).expanduser() if configured else DEFAULT_DB_PATH

def configure_connection(conn: sqlite3.Connection) -> sqlite3.Connection:
    """Apply Mnemoir's standard SQLite safety/concurrency pragmas.

    Live Hermes deployments can have several profile gateways reading the Mnemoir
    database while the hourly overflow sweep needs to preserve and trim memory
    blocks. A short/default SQLite busy timeout lets transient WAL writer
    contention surface as ``database is locked`` and can leave MEMORY.md above
    the trim threshold for hours. Keep every Mnemoir connection patient enough for
    normal live-gateway contention before declaring a real failure.
    """
    conn.row_factory = sqlite3.Row
    conn.execute(f'PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}')
    conn.execute('PRAGMA foreign_keys = ON')
    try:
        conn.execute('PRAGMA journal_mode = WAL')
    except sqlite3.DatabaseError:
        pass
    return conn

def connect(db_path: str | Path | None=None) -> sqlite3.Connection:
    path = resolve_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=SQLITE_BUSY_TIMEOUT_SECONDS)
    return configure_connection(conn)

def initialize_database(conn: sqlite3.Connection, schema_path: Any=None) -> None:
    schema_resource = schema_path or SCHEMA_PATH
    schema = schema_resource.read_text(encoding='utf-8')
    last_error: sqlite3.OperationalError | None = None
    for attempt in range(1, 9):
        try:
            configure_connection(conn)
            conn.executescript(schema)
            _apply_additive_schema_migrations(conn)
            conn.commit()
            return
        except sqlite3.OperationalError as exc:
            if 'database is locked' not in str(exc).lower() and 'database table is locked' not in str(exc).lower() and ('database is busy' not in str(exc).lower()):
                raise
            last_error = exc
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
            if attempt == 8:
                break
            time.sleep(min(5.0, 0.25 * 2 ** (attempt - 1)))
    raise sqlite3.OperationalError(f'database is locked after initialize retry: {last_error}')

def _apply_additive_schema_migrations(conn: sqlite3.Connection) -> None:
    """Bring pre-17A live databases forward without rebuilding or deleting data.

    ``CREATE TABLE IF NOT EXISTS`` cannot add columns to an existing table. The
    live Mnemoir database predates the final compat 17A journal binding columns, so a
    clean install passed while the real lifecycle failed at its first insert.
    Keep upgrades explicit, additive, and idempotent.
    """
    existing = {row[1] for row in conn.execute('PRAGMA table_info(writeback_operations)')}
    additions = {'allowed_root_hash': 'TEXT', 'target_parent_dev': 'INTEGER', 'target_parent_ino': 'INTEGER', 'operation_type': 'TEXT', 'proposal_id': 'TEXT'}
    added_any = False
    for name, sql_type in additions.items():
        if name not in existing:
            conn.execute(f'ALTER TABLE writeback_operations ADD COLUMN {name} {sql_type}')
            added_any = True
    if added_any:
        conn.execute("UPDATE writeback_operations\n               SET error_code=COALESCE(error_code, 'legacy_binding_unavailable:' || state),\n                   state='legacy_manual_recovery_required'\n               WHERE (allowed_root_hash IS NULL OR target_parent_dev IS NULL OR target_parent_ino IS NULL OR operation_type IS NULL)\n                 AND state NOT IN ('completed','completed_partial','blocked_target_unreachable','rolled_back','failed_before_mutation','legacy_manual_recovery_required')")

def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}
