"""Explicit, leak-safe Hermes plugin onboarding diagnostics and bootstrap."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
from typing import Any

from .db import connect, initialize_database
from .hermes_provider import HermesProviderError, context_packet_for_profile, ingest_profile_markdown
from .plugin_install import default_plugin_storage

_SCHEMA_VERSION = "mnemoir-plugin-bootstrap-profile-v1"
_PROVIDER_ID = "mnemoir_provenance"
_LEGACY_PROVIDER_ID = "council" + "_memory_core"
_SOURCE_FAMILY = "hermes_profile_memory"
_PROFILE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SIDE_EFFECTS = {
    "config_mutated": False,
    "provider_selected": False,
    "gateway_restart_performed": False,
    "promotion_performed": False,
    "writeback_performed": False,
}
_ZERO_COUNTS = {
    "source_count": 0,
    "raw_event_count": 0,
    "evidence_count": 0,
    "recall_result_count": 0,
}


def _safe_directory(path: Path, *, require_private: bool = False) -> bool:
    try:
        if not path.is_absolute() or ".." in path.parts or not path.exists():
            return False
        if any(part in {"", ".", ".."} for part in path.parts[1:]):
            return False
        current = Path(path.anchor)
        for part in path.parts[1:]:
            current /= part
            if current.is_symlink():
                return False
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode):
            return False
        if require_private and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
            return False
        return True
    except OSError:
        return False


def _base(profile_id: str | None, counts: dict[str, int] | None = None) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "operation": "bootstrap_profile",
        "provider_id": _PROVIDER_ID,
        "profile_id": profile_id,
        "source_family": _SOURCE_FAMILY,
        "counts": dict(counts or _ZERO_COUNTS),
        "idempotent_replay": False,
        "ingest_committed": False,
        "recall_status": "not_run",
        "citations": [],
        **_SIDE_EFFECTS,
    }


def _failure(
    code: str,
    message: str,
    *,
    stage: str,
    exit_code: int,
    profile_id: str | None,
    counts: dict[str, int] | None = None,
    committed: bool = False,
    recall_status: str = "not_run",
    idempotent_replay: bool = False,
    retryable: bool = False,
) -> tuple[int, dict[str, Any]]:
    result = _base(profile_id, counts)
    result.update(
        {
            "status": "error",
            "idempotent_replay": idempotent_replay,
            "ingest_committed": committed,
            "recall_status": recall_status,
            "error": {
                "code": code,
                "message": message,
                "retryable": retryable,
                "stage": stage,
                "exit_code": exit_code,
            },
        }
    )
    return exit_code, result


def _runtime_probe(hermes_home: Path, python: Path) -> dict[str, Any]:
    code = (
        "import json; "
        "out={'package_importable':False,'hermes_loader_importable':False,"
        "'provider_discoverable':False,'provider_available':False}; "
        "import mnemoir_provenance as p; out['package_importable']=True; "
        "from plugins.memory import discover_memory_providers; "
        "out['hermes_loader_importable']=True; "
        "rows=discover_memory_providers(); "
        "out['provider_discoverable']=any(r[0]=='mnemoir_provenance' for r in rows); "
        "out['provider_available']=any(r[0]=='mnemoir_provenance' and bool(r[2]) for r in rows); "
        "print(json.dumps(out,sort_keys=True))"
    )
    env = os.environ.copy()
    env["HERMES_HOME"] = str(hermes_home)
    try:
        process = subprocess.run(
            [str(python), "-c", code],
            env=env,
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "error"}
    if process.returncode != 0:
        return {"status": "error"}
    try:
        result = json.loads(process.stdout)
    except (json.JSONDecodeError, TypeError):
        return {"status": "error"}
    return {"status": "ok", **result}


def plugin_status(
    hermes_home: str | Path,
    *,
    hermes_python: str | Path | None = None,
) -> dict[str, Any]:
    """Diagnose package/plugin/storage readiness without mutating anything."""
    home = Path(hermes_home).expanduser()
    python = Path(hermes_python or sys.executable).expanduser()
    parent, database = default_plugin_storage(home)
    plugin = home / "plugins" / "mnemoir_provenance"
    base = {
        "operation": "plugin_status",
        "provider_id": _PROVIDER_ID,
        "plugin_present": (plugin / "__init__.py").is_file() and (plugin / "plugin.yaml").is_file(),
        "default_storage_parent_ready": _safe_directory(parent, require_private=True),
        "database_state": "present" if database.is_file() else "empty",
        "provider_selection_state": "not_checked_use_hermes_memory_status",
        "selection_authority": "hermes memory status",
        "legacy_private_provider_present": (home / "plugins" / _LEGACY_PROVIDER_ID).is_dir(),
        **_SIDE_EFFECTS,
    }
    if not _safe_directory(home):
        return {
            **base,
            "status": "error",
            "error": {"code": "hermes_home_invalid", "stage": "preflight", "message": "Hermes home is missing or unsafe."},
        }
    probe = _runtime_probe(home, python)
    if probe.get("status") != "ok":
        return {
            **base,
            "status": "error",
            "error": {
                "code": "package_not_importable_in_hermes_runtime",
                "stage": "preflight",
                "message": "Use the Hermes Python interpreter with -m pip install 'mnemoir-provenance[hermes]', then rerun plugin status.",
            },
        }
    result = {**base, **{key: value for key, value in probe.items() if key != "status"}}
    if not base["plugin_present"] or not base["default_storage_parent_ready"] or not probe.get("provider_available"):
        result.update(
            {
                "status": "degraded",
                "error": {
                    "code": "plugin_not_ready",
                    "stage": "preflight",
                    "message": "Run the explicit plugin installer in the same Python runtime, then rerun plugin status.",
                },
            }
        )
    else:
        result["status"] = "ok"
    return result


def _profile_fixture_preflight(root: Path) -> str | None:
    if not _safe_directory(root):
        return "profile_root_denied"
    if ".hermes" in {part.lower() for part in root.parts} and "profiles" in {part.lower() for part in root.parts}:
        return "profile_root_denied"
    nonempty = False
    for name in ("MEMORY.md", "USER.md"):
        path = root / name
        try:
            if path.is_symlink():
                return "profile_root_denied"
            if path.exists():
                metadata = path.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    return "profile_root_denied"
                if metadata.st_size > 0:
                    nonempty = True
        except OSError:
            return "profile_root_denied"
    return None if nonempty else "profile_fixture_empty"


def _profile_counts(conn: sqlite3.Connection, profile_id: str) -> dict[str, int]:
    source_count = conn.execute(
        "SELECT COUNT(*) FROM sources WHERE profile_id=? AND source_type='hermes_markdown_overflow'",
        (profile_id,),
    ).fetchone()[0]
    raw_count = conn.execute(
        "SELECT COUNT(*) FROM raw_events r JOIN sources s ON s.source_id=r.source_id WHERE s.profile_id=? AND s.source_type='hermes_markdown_overflow'",
        (profile_id,),
    ).fetchone()[0]
    evidence_count = conn.execute(
        "SELECT COUNT(*) FROM evidence_items e JOIN sources s ON s.source_id=e.source_id WHERE s.profile_id=? AND s.source_type='hermes_markdown_overflow'",
        (profile_id,),
    ).fetchone()[0]
    return {
        "source_count": int(source_count),
        "raw_event_count": int(raw_count),
        "evidence_count": int(evidence_count),
        "recall_result_count": 0,
    }


def bootstrap_profile(
    *,
    hermes_home: str | Path,
    profile_root: str | Path,
    profile_id: str,
    verify_query: str,
    db_path: str | Path | None = None,
    require_hermes_runtime: bool = True,
) -> tuple[int, dict[str, Any]]:
    """Explicitly ingest one controlled profile fixture and verify cited recall."""
    home = Path(hermes_home).expanduser()
    root = Path(profile_root).expanduser()
    if not _PROFILE_ID.fullmatch(str(profile_id)):
        return _failure("profile_scope_invalid", "Profile ID is invalid.", stage="preflight", exit_code=2, profile_id=None)
    if not _safe_directory(home):
        return _failure("hermes_home_invalid", "Hermes home is missing or unsafe.", stage="preflight", exit_code=2, profile_id=None)
    plugin = home / "plugins" / "mnemoir_provenance"
    if not (plugin / "__init__.py").is_file() or not (plugin / "plugin.yaml").is_file():
        return _failure("hermes_home_invalid", "Explicit plugin installation is required before bootstrap.", stage="preflight", exit_code=2, profile_id=None)
    default_parent, default_database = default_plugin_storage(home)
    if db_path is None:
        if not _safe_directory(default_parent, require_private=True):
            return _failure("default_storage_parent_unsafe", "Default storage parent is missing or unsafe; rerun explicit plugin install.", stage="preflight", exit_code=2, profile_id=None)
        database = default_database
    else:
        database = Path(db_path).expanduser()
        if not database.is_absolute() or ".." in database.parts or not _safe_directory(database.parent):
            return _failure("custom_db_parent_missing", "Custom database parent must already exist and be a safe directory.", stage="preflight", exit_code=2, profile_id=None)
    if require_hermes_runtime:
        runtime = plugin_status(home)
        if runtime.get("status") == "error" or not runtime.get("package_importable") or not runtime.get("hermes_loader_importable"):
            return _failure(
                "package_not_importable_in_hermes_runtime",
                "Install 'mnemoir-provenance[hermes]' with the Hermes Python interpreter and rerun bootstrap.",
                stage="preflight",
                exit_code=2,
                profile_id=None,
            )
    fixture_error = _profile_fixture_preflight(root)
    if fixture_error:
        message = "Controlled profile fixture is empty." if fixture_error == "profile_fixture_empty" else "Controlled profile root is denied or unsafe."
        return _failure(fixture_error, message, stage="preflight", exit_code=2, profile_id=None)
    if not str(verify_query).strip():
        return _failure("bootstrap_recall_failed", "Verification query must be non-empty.", stage="recall", exit_code=4, profile_id=profile_id, committed=True, recall_status="error")

    try:
        with connect(database) as conn:
            initialize_database(conn)
            ingest = ingest_profile_markdown(
                conn,
                profile_id,
                root,
                allowed_profile_roots=[root.parent],
            )
            counts = _profile_counts(conn, profile_id)
            replay = ingest.get("inserted_raw_events", 0) == 0 and counts["raw_event_count"] > 0
            if ingest.get("status") != "ok" or counts["evidence_count"] == 0:
                return _failure(
                    "bootstrap_ingest_failed",
                    "Controlled profile ingest failed or produced no evidence.",
                    stage="ingest",
                    exit_code=3,
                    profile_id=profile_id,
                    counts=counts,
                    idempotent_replay=replay,
                    retryable=True,
                )
            try:
                packet = context_packet_for_profile(
                    conn,
                    str(verify_query),
                    profile_id=profile_id,
                    limit=5,
                )
            except Exception:
                return _failure(
                    "bootstrap_recall_failed",
                    "Cited recall verification failed.",
                    stage="recall",
                    exit_code=4,
                    profile_id=profile_id,
                    counts=counts,
                    committed=True,
                    recall_status="error",
                    idempotent_replay=replay,
                    retryable=True,
                )
            cited = packet.get("cited_context", [])
            counts["recall_result_count"] = len(cited)
            if not cited:
                return _failure(
                    "bootstrap_no_cited_match",
                    "No cited match was found for the verification query.",
                    stage="recall",
                    exit_code=4,
                    profile_id=profile_id,
                    counts=counts,
                    committed=True,
                    recall_status="no_cited_match",
                    idempotent_replay=replay,
                    retryable=True,
                )
            empty_probe_token = "zzzzemptyprobe" + hashlib.sha256(
                f"{profile_id}:{counts['source_count']}:{counts['evidence_count']}".encode("utf-8")
            ).hexdigest()
            try:
                empty_packet = context_packet_for_profile(
                    conn,
                    empty_probe_token,
                    profile_id=profile_id,
                    limit=1,
                )
            except Exception:
                return _failure(
                    "bootstrap_recall_failed",
                    "Empty/degraded recall verification failed.",
                    stage="recall",
                    exit_code=4,
                    profile_id=profile_id,
                    counts=counts,
                    committed=True,
                    recall_status="error",
                    idempotent_replay=replay,
                    retryable=True,
                )
            if empty_packet.get("cited_context"):
                return _failure(
                    "bootstrap_recall_failed",
                    "Empty/degraded recall verification returned unexpected cited context.",
                    stage="recall",
                    exit_code=4,
                    profile_id=profile_id,
                    counts=counts,
                    committed=True,
                    recall_status="error",
                    idempotent_replay=replay,
                    retryable=True,
                )
            citations = [
                {
                    "source_id": item["citation"]["source_id"],
                    "source_pointer": item["citation"]["source_pointer"],
                    "content_hash": item["citation"]["content_hash"],
                }
                for item in cited
            ]
            result = _base(profile_id, counts)
            result.update(
                {
                    "status": "ok",
                    "idempotent_replay": replay,
                    "ingest_committed": True,
                    "recall_status": "ok",
                    "citations": citations,
                }
            )
            return 0, result
    except (HermesProviderError, OSError, sqlite3.Error, ValueError):
        return _failure(
            "bootstrap_ingest_failed",
            "Controlled profile ingest failed.",
            stage="ingest",
            exit_code=3,
            profile_id=profile_id,
            retryable=True,
        )
