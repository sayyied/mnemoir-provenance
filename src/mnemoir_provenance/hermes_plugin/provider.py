"""Mnemoir Provenance Hermes MemoryProvider plugin.

This adapter is intentionally inert until a Hermes profile explicitly selects
``memory.provider: mnemoir_provenance``. It does not mutate Hermes config,
restart gateways, or call Honcho. Profile Markdown is read, and may be written,
only when the operator also selects the bounded ``live_overflow_trim`` policy;
other writeback modes remain non-mutating.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.memory_provider import MemoryProvider
from tools.registry import tool_error

from mnemoir_provenance.audit import write_audit_event
from mnemoir_provenance.curation import CurationError, create_proposal
from mnemoir_provenance.db import connect, initialize_database, now_utc
from mnemoir_provenance.live_overflow import live_overflow_status, run_live_overflow_coordinator
from mnemoir_provenance.hermes_provider import (
    context_packet,
    markdown_writeback_status,
    overflow_compaction_plan_status,
    overflow_pressure_status,
    provider_status,
    ingest_profile_markdown,
    import_honcho_legacy_fixture,
    propose_completed_turn_sync,
)
from mnemoir_provenance.source_adapters import import_obsidian_vault_fixture, import_session_search_fixture
from mnemoir_provenance.tool_gating import ToolGatingRequest, evaluate_mnemoir_tool_gating

_PLUGIN_NAME = "mnemoir_provenance"
_DEFAULT_MODE = "proposal_only"
_DEFAULT_RECALL_MODE = "hybrid"
_DEFAULT_SYNC_TURN_POLICY = "audit_only"
_DEFAULT_WRITEBACK_MODE = "propose_only"
_DEFAULT_CONTEXT_BUDGET_CHARS = 4000

_SESSION_SEARCH_IMPORT_SCHEMA = {
    "name": "cmc_import_session_search",
    "description": "Import an explicitly supplied controlled session_search JSON/JSONL export fixture into Mnemoir as profile-scoped source/raw_event/evidence/provenance rows. Never reads the live session DB or dumps raw private transcript content in status output.",
    "parameters": {
        "type": "object",
        "properties": {
            "session_fixture_path": {"type": "string", "description": "Controlled local JSON/JSONL session_search export fixture path."}
        },
        "required": ["session_fixture_path"],
    },
}

_OBSIDIAN_IMPORT_SCHEMA = {
    "name": "cmc_import_obsidian_vault",
    "description": "Import an explicitly supplied controlled Obsidian vault fixture into Mnemoir as profile-scoped source/raw_event/evidence/provenance rows with redacted relative pointers. Does not crawl unrestricted vaults or treat derived Wiki projections as canonical by default.",
    "parameters": {
        "type": "object",
        "properties": {
            "vault_root": {"type": "string", "description": "Controlled local Obsidian vault fixture root."},
            "include_derived_projection": {"type": "boolean", "description": "Explicitly mark generated projection pages as supplied controlled source input. Default false."},
        },
        "required": ["vault_root"],
    },
}

_HONCHO_IMPORT_SCHEMA = {
    "name": "cmc_import_honcho_legacy",
    "description": "Import an explicitly supplied controlled local Honcho export fixture into Mnemoir as source-grounded legacy draft/proposal records. Never calls live Honcho APIs, reads profile markdown, writes markdown, or mutates Hermes config.",
    "parameters": {
        "type": "object",
        "properties": {
            "honcho_fixture_path": {"type": "string", "description": "Controlled local JSON/JSONL Honcho export fixture path."}
        },
        "required": ["honcho_fixture_path"],
    },
}

_CONTEXT_SCHEMA = {
    "name": "cmc_context",
    "description": "Return cited, source-grounded local Mnemoir Provenance context for a query. Empty/degraded status is explicit; uncited recall is not allowed.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Query for local Mnemoir recall."},
            "limit": {"type": "integer", "description": "Maximum cited context items, default 5, max 10."},
            "context_budget_chars": {"type": "integer", "description": "Deterministic JSON character budget for the packed cited context payload, default 4000."},
        },
        "required": ["query"],
    },
}

_SEARCH_SCHEMA = {
    "name": "cmc_search",
    "description": "Search Mnemoir Provenance local memory/evidence and return cited JSON results with source coverage/degradation status.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "Search query."},
            "limit": {"type": "integer", "description": "Maximum results, default 5, max 10."},
        },
        "required": ["query"],
    },
}

_SOURCES_SCHEMA = {
    "name": "cmc_sources",
    "description": "Report redacted Mnemoir Provenance source coverage and degraded-source posture. Does not expose profile paths or secrets.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}

_PROPOSE_SCHEMA = {
    "name": "cmc_propose_memory",
    "description": "Create a source-grounded Mnemoir memory proposal. This does not write MEMORY.md/USER.md and requires explicit evidence_ids or source_event_ids.",
    "parameters": {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "summary": {"type": "string"},
            "body": {"type": "string"},
            "evidence_ids": {"type": "array", "items": {"type": "string"}},
            "source_event_ids": {"type": "array", "items": {"type": "string"}},
            "privacy_class": {"type": "string", "enum": ["public", "internal", "private", "sensitive"]},
        },
        "required": ["title", "summary", "body"],
    },
}

_WRITEBACK_STATUS_SCHEMA = {
    "name": "cmc_writeback_status",
    "description": "Report Mnemoir real profile markdown writeback posture, including compat 15.8 live-overflow trim/writeback mode when configured.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}

_OVERFLOW_PRESSURE_SCHEMA = {
    "name": "cmc_overflow_pressure",
    "description": "Report MEMORY.md/USER.md pressure metrics for a caller-supplied controlled temporary fixture root only. Does not read live profile markdown or mutate files.",
    "parameters": {
        "type": "object",
        "properties": {
            "fixture_root": {"type": "string", "description": "Temporary controlled fixture root containing MEMORY.md and/or USER.md."}
        },
        "required": ["fixture_root"],
    },
}

_OVERFLOW_PLAN_SCHEMA = {
    "name": "cmc_overflow_plan",
    "description": "Return a proposal-only MEMORY.md/USER.md trim/compaction plan from already-ingested Mnemoir overflow rows. Does not read or write markdown files.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}


_SYNC_TURN_PROPOSAL_SCHEMA = {
    "name": "cmc_sync_turn_proposal",
    "description": "Create a proposal-only memory candidate from a controlled completed-turn JSON fixture. Does not promote memory, write markdown, activate provider config, or call Honcho.",
    "parameters": {
        "type": "object",
        "properties": {
            "turn_fixture_path": {"type": "string", "description": "Controlled temporary JSON fixture path containing user_content and assistant_content."}
        },
        "required": ["turn_fixture_path"],
    },
}

_INGEST_PROFILE_SCHEMA = {
    "name": "cmc_ingest_profile_markdown",
    "description": "Read-only ingest explicitly supplied controlled fixture/profile root MEMORY.md/USER.md through the Mnemoir provider path. Disabled unless root is controlled temporary or configured controlled_profile_roots. Never writes markdown or mutates Hermes config.",
    "parameters": {
        "type": "object",
        "properties": {
            "profile_root": {"type": "string", "description": "Controlled temporary fixture/profile root containing MEMORY.md and/or USER.md."}
        },
        "required": ["profile_root"],
    },
}


def _load_yaml_council_config(path: Path) -> dict[str, Any]:
    """Parse the minimal non-secret mnemoir_provenance config block Hermes loads.

    The isolated activation harness writes only flat scalar/list values, so this
    deliberately avoids adding a YAML dependency or interpreting unrelated
    config/provider/auth sections.
    """
    if not path.exists():
        return {}
    result: dict[str, Any] = {}
    in_block = False
    current_list_key: str | None = None
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if not raw_line.startswith(" "):
            in_block = raw_line.strip() == "mnemoir_provenance:"
            current_list_key = None
            continue
        if not in_block:
            continue
        stripped = raw_line.strip()
        if stripped.startswith("- ") and current_list_key:
            result.setdefault(current_list_key, []).append(stripped[2:].strip().strip('"\''))
            continue
        current_list_key = None
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value == "":
            result[key] = []
            current_list_key = key
        elif value.lower() in {"true", "false"}:
            result[key] = value.lower() == "true"
        elif value.startswith("[") and value.endswith("]"):
            result[key] = [item.strip().strip('"\'') for item in value[1:-1].split(",") if item.strip()]
        else:
            result[key] = value.strip('"\'')
    return result


def _load_config(hermes_home: str | Path | None = None) -> dict[str, Any]:
    """Load profile-scoped Mnemoir plugin config without requiring secrets."""
    home = Path(hermes_home).expanduser() if hermes_home else None
    cfg: dict[str, Any] = {
        "db_path": os.environ.get("MNEMOIR_DB", ""),
        "mode": os.environ.get("MNEMOIR_MODE", _DEFAULT_MODE),
        "recall_mode": os.environ.get("MNEMOIR_RECALL_MODE", _DEFAULT_RECALL_MODE),
        "sync_turn_policy": os.environ.get("MNEMOIR_SYNC_TURN_POLICY", _DEFAULT_SYNC_TURN_POLICY),
        "writeback_mode": os.environ.get("MNEMOIR_WRITEBACK_MODE", _DEFAULT_WRITEBACK_MODE),
        "ingest_on_start": False,
        "source_policy": ["cmc_db"],
        "source_families": ["hermes_markdown_overflow", "hermes_profile_memory"],
        "controlled_profile_roots": [],
        "controlled_turn_roots": [],
        "controlled_honcho_import_roots": [],
        "controlled_session_search_roots": [],
        "controlled_obsidian_vault_roots": [],
        "context_budget_chars": _DEFAULT_CONTEXT_BUDGET_CHARS,
    }
    if home:
        yaml_path = home / "config.yaml"
        try:
            cfg.update({k: v for k, v in _load_yaml_council_config(yaml_path).items() if v is not None})
        except Exception:
            cfg["config_error"] = "invalid_mnemoir_provenance_yaml"
        path = home / "mnemoir_provenance.json"
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    cfg.update({k: v for k, v in loaded.items() if v is not None})
            except Exception:
                cfg["config_error"] = "invalid_mnemoir_provenance_json"
    return cfg


def _default_db_path(hermes_home: str | Path) -> str:
    return str(Path(hermes_home).expanduser() / "mnemoir-provenance" / "mnemoir_provenance.sqlite")


def _json_result(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True)


def _limit(value: Any, default: int = 5, maximum: int = 10) -> int:
    try:
        n = int(value)
    except Exception:
        n = default
    return max(1, min(maximum, n))


class CouncilMemoryCoreProvider(MemoryProvider):
    """Hermes MemoryProvider wrapper over the local Mnemoir Provenance DB."""

    def __init__(self) -> None:
        self._config: dict[str, Any] = {}
        self._db_path = ""
        self._session_id = ""
        self._hermes_home = ""
        self._platform = ""
        self._agent_identity = "default"
        self._conn = None
        self._conn_thread_id: int | None = None
        self._last_status: dict[str, Any] = {"status": "not_initialized"}

    @property
    def name(self) -> str:
        return _PLUGIN_NAME

    def is_available(self) -> bool:
        """Cheap local readiness check: importable plus configured DB target.

        This intentionally performs no network or Honcho calls and does not open
        or create the SQLite database during provider discovery. Initialization is
        responsible for creating a missing local DB. Discovery fails closed only
        when Hermes has no active home, Mnemoir is not importable, or no DB target can
        be resolved.
        """
        try:
            import mnemoir_provenance  # noqa: F401
        except Exception:
            return False
        hermes_home = os.environ.get("HERMES_HOME")
        if not hermes_home:
            return False
        cfg = _load_config(hermes_home)
        db_path = str(cfg.get("db_path") or _default_db_path(hermes_home)).strip()
        if not db_path:
            return False
        try:
            path = Path(db_path).expanduser()
            return bool(path.name) and path.parent.exists()
        except Exception:
            return False

    def get_config_schema(self) -> List[Dict[str, Any]]:
        return [
            {"key": "db_path", "description": "Local Mnemoir Provenance SQLite DB path. Defaults to a profile-scoped path under HERMES_HOME.", "required": False},
            {"key": "mode", "description": "Runtime mode", "default": _DEFAULT_MODE, "choices": ["read_only", "proposal_only"]},
            {"key": "recall_mode", "description": "Recall exposure mode", "default": _DEFAULT_RECALL_MODE, "choices": ["context", "tools", "hybrid"]},
            {"key": "sync_turn_policy", "description": "Completed-turn sync policy", "default": _DEFAULT_SYNC_TURN_POLICY, "choices": ["off", "audit_only", "proposal_only"]},
            {"key": "writeback_mode", "description": "Real profile markdown overflow writeback posture", "default": _DEFAULT_WRITEBACK_MODE, "choices": ["disabled", "propose_only", "live_overflow_trim"]},
            {"key": "ingest_on_start", "description": "Whether to ingest configured sources on provider initialization", "default": "false", "choices": ["false"]},
            {"key": "controlled_profile_roots", "description": "Optional explicit controlled fixture roots allowed for read-only profile markdown ingestion. Live Hermes profile roots remain denied.", "required": False},
            {"key": "controlled_turn_roots", "description": "Optional explicit controlled fixture roots allowed for completed-turn proposal generation. Live Hermes profile roots remain denied.", "required": False},
            {"key": "controlled_honcho_import_roots", "description": "Optional explicit controlled fixture roots allowed for Honcho legacy import dry runs. Live Honcho APIs and live Hermes profile roots remain denied.", "required": False},
            {"key": "context_budget_chars", "description": "Default deterministic JSON character budget for Mnemoir packed context payloads.", "default": str(_DEFAULT_CONTEXT_BUDGET_CHARS), "required": False},
        ]

    def save_config(self, values: dict[str, Any], hermes_home: str | Path) -> None:
        """Write non-secret plugin config. Does not set memory.provider."""
        path = Path(hermes_home) / "mnemoir_provenance.json"
        existing: dict[str, Any] = {}
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}
        existing.update(values)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")

    def initialize(self, session_id: str, **kwargs: Any) -> None:
        self._session_id = session_id or ""
        self._hermes_home = str(kwargs.get("hermes_home") or os.environ.get("HERMES_HOME") or Path.home() / ".hermes")
        self._platform = str(kwargs.get("platform") or "unknown")
        self._agent_identity = str(kwargs.get("agent_identity") or "default")
        self._config = _load_config(self._hermes_home)
        self._db_path = str(self._config.get("db_path") or _default_db_path(self._hermes_home))
        conn = self._open_operation_conn()
        try:
            audit_id = write_audit_event(
                conn,
                event_type="hermes.plugin.initialize",
                target_type="memory_provider",
                target_id=_PLUGIN_NAME,
                status="ok",
                metadata={
                    "provider": _PLUGIN_NAME,
                    "session_id": self._session_id,
                    "platform": self._platform,
                    "agent_identity": self._agent_identity,
                    "mode": self._config.get("mode", _DEFAULT_MODE),
                    "recall_mode": self._config.get("recall_mode", _DEFAULT_RECALL_MODE),
                    "sync_turn_policy": self._config.get("sync_turn_policy", _DEFAULT_SYNC_TURN_POLICY),
                    "writeback_mode": self._config.get("writeback_mode", _DEFAULT_WRITEBACK_MODE),
                    "honcho_api_required": False,
                    "gateway_restart_performed": False,
                    "real_profile_markdown_writeback": False,
                    "real_profile_markdown_writeback_capable": self._config.get("writeback_mode") == "live_overflow_trim",
                    "automatic_policy_authority": "operator_selected_durable_policy" if self._config.get("writeback_mode") == "live_overflow_trim" else "none",
                    "markdown_ingest_on_start": False,
                    "honcho_import_on_start": False,
                    "honcho_api_called": False,
                },
            )
            conn.commit()
        finally:
            conn.close()
        for module_name in list(sys.modules):
            if module_name == "plugins.memory.honcho" or module_name.startswith("plugins.memory.honcho."):
                sys.modules.pop(module_name, None)
        self._last_status = {
            "status": "ok",
            "provider": _PLUGIN_NAME,
            "selected_memory_provider": _PLUGIN_NAME,
            "selected_provider_active": True,
            "initialized": True,
            "audit_id": audit_id,
            "mode": self._config.get("mode", _DEFAULT_MODE),
            "recall_mode": self._config.get("recall_mode", _DEFAULT_RECALL_MODE),
            "sync_turn_policy": self._config.get("sync_turn_policy", _DEFAULT_SYNC_TURN_POLICY),
            "writeback_mode": self._config.get("writeback_mode", _DEFAULT_WRITEBACK_MODE),
            "honcho_active": False,
            "honcho_selected_provider": False,
            "honcho_api_required": False,
            "live_config_mutation_performed": False,
            "markdown_ingest_on_start": False,
            "profile_markdown_read_performed": False,
            "honcho_import_on_start": False,
            "honcho_api_called": False,
        }
        # Live-overflow mode performs bounded startup catch-up through the
        # hash-bound compat 17A transaction engine. Other modes remain inert.
        if self._config.get("writeback_mode") == "live_overflow_trim":
            operation_conn = self._open_operation_conn()
            try:
                self._last_status["live_overflow_trim"] = run_live_overflow_coordinator(
                    operation_conn, profile_ids=(self._agent_identity,), hermes_home=self._hermes_home
                )
                live_result = self._last_status["live_overflow_trim"]
                live_audit_id = write_audit_event(
                    operation_conn,
                    event_type="hermes.plugin.live_overflow",
                    target_type="memory_provider",
                    target_id=_PLUGIN_NAME,
                    status={"succeeded":"ok","partial":"warning"}.get(str(live_result.get("status")),"error"),
                    metadata={
                        "provider": _PLUGIN_NAME,
                        "trigger": "initialize",
                        "writeback_mode": "live_overflow_trim",
                        "automatic_policy_authority": "operator_selected_durable_policy",
                        "file_mutation_performed": bool(live_result.get("file_mutation_performed")),
                        "mutated_file_count": int(live_result.get("mutated_file_count") or 0),
                        "unresolved_count": int(live_result.get("unresolved_count") or 0),
                        "content_included": False,
                        "path_redacted": True,
                    },
                )
                operation_conn.commit()
                self._last_status["live_overflow_audit_id"] = live_audit_id
            finally:
                operation_conn.close()

    def _run_live_overflow_trim(self, *, trigger: str) -> dict[str, Any]:
        """Run bounded catch-up through the protected overflow coordinator."""
        if self._config.get("writeback_mode", _DEFAULT_WRITEBACK_MODE) != "live_overflow_trim":
            return {"status": "disabled", "trigger": trigger, "file_mutation_performed": False}
        conn = self._open_operation_conn()
        try:
            result = run_live_overflow_coordinator(
                conn, profile_ids=(self._agent_identity,), hermes_home=self._hermes_home
            )
            audit_id = write_audit_event(
                conn,
                event_type="hermes.plugin.live_overflow",
                target_type="memory_provider",
                target_id=_PLUGIN_NAME,
                status={"succeeded":"ok","partial":"warning"}.get(str(result.get("status")),"error"),
                metadata={
                    "provider": _PLUGIN_NAME,
                    "trigger": trigger,
                    "writeback_mode": "live_overflow_trim",
                    "automatic_policy_authority": "operator_selected_durable_policy",
                    "file_mutation_performed": bool(result.get("file_mutation_performed")),
                    "mutated_file_count": int(result.get("mutated_file_count") or 0),
                    "unresolved_count": int(result.get("unresolved_count") or 0),
                    "content_included": False,
                    "path_redacted": True,
                },
            )
            conn.commit()
            result["audit_id"] = audit_id
        finally:
            conn.close()
        result["trigger"] = trigger
        self._last_status["live_overflow_trim"] = result
        return result

    def _open_operation_conn(self):
        """Open a short-lived Mnemoir connection for one provider operation.

        Gateway providers live for the process lifetime. Keeping the SQLite
        handle open across turns leaves the gateway holding DB/WAL/SHM fds and
        can starve the hourly overflow catch-up writer. Provider operations are
        small and already commit explicitly, so open, use, commit/rollback in the
        operation, and close immediately.
        """
        if not self._db_path:
            raise RuntimeError("mnemoir_provenance_provider_not_initialized")
        conn = connect(self._db_path)
        initialize_database(conn)
        return conn

    def _ensure_conn(self):
        current_thread_id = threading.get_ident()
        if self._conn is not None and self._conn_thread_id != current_thread_id:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
            self._conn_thread_id = None
        if self._conn is None:
            if not self._db_path:
                raise RuntimeError("mnemoir_provenance_provider_not_initialized")
            self._conn = connect(self._db_path)
            self._conn_thread_id = current_thread_id
            initialize_database(self._conn)
        return self._conn

    def system_prompt_block(self) -> str:
        if not self._last_status.get("initialized"):
            return ""
        mode = self._config.get("mode", _DEFAULT_MODE)
        return (
            "Mnemoir Provenance is the selected local memory provider for this Hermes profile. "
            "Use only cited Mnemoir context as authoritative memory evidence; degraded or empty Mnemoir recall means no local memory claim is supported. "
            f"Runtime posture: mode={mode}, writeback_mode={self._config.get('writeback_mode', _DEFAULT_WRITEBACK_MODE)}, Honcho API not required."
        )

    def _format_prefetch(self, packet: dict[str, Any]) -> str:
        cited = packet.get("cited_context") or []
        if not cited:
            warnings = ",".join(packet.get("warnings") or ["no_cited_context_available"])
            return f"Mnemoir Provenance: degraded/empty local recall ({warnings}). Do not infer unsupported memory."
        lines = ["Mnemoir Provenance local cited context:"]
        for item in cited[:5]:
            citation = item.get("citation", {})
            lines.append(
                f"- source_id={item.get('source_id')} target_type={item.get('target_type')} "
                f"target_id={item.get('target_id')} proposal_id={citation.get('proposal_id')} "
                f"memory_version={citation.get('memory_version')} pointer={citation.get('source_pointer')} "
                f"hash={citation.get('content_hash')}: {item.get('snippet')}"
            )
        if packet.get("warnings"):
            lines.append("Warnings: " + ", ".join(packet["warnings"]))
        return "\n".join(lines)

    def _configured_source_families(self) -> tuple[str, ...]:
        families = self._config.get("source_families") or ["hermes_markdown_overflow", "hermes_profile_memory"]
        if not isinstance(families, (list, tuple)):
            families = ["hermes_markdown_overflow", "hermes_profile_memory"]
        safe = []
        for family in families:
            value = str(family).strip()
            if value and value not in safe:
                safe.append(value)
        return tuple(safe or ["hermes_markdown_overflow", "hermes_profile_memory"])

    def prefetch(self, query: str, *, session_id: str = "") -> str:
        if self._config.get("recall_mode", _DEFAULT_RECALL_MODE) not in {"context", "hybrid"}:
            return ""
        conn = self._open_operation_conn()
        try:
            packet = context_packet(conn, query, profile_id=self._agent_identity, limit=5, source_families=self._configured_source_families(), context_budget_chars=self._config.get("context_budget_chars", _DEFAULT_CONTEXT_BUDGET_CHARS))
        finally:
            conn.close()
        return self._format_prefetch(packet)

    def queue_prefetch(self, query: str, *, session_id: str = "") -> None:
        return None

    def sync_turn(self, user_content: str, assistant_content: str, *, session_id: str = "", messages: Optional[List[Dict[str, Any]]] = None) -> None:
        # The provider can remain alive for days while Hermes memory tooling grows
        # profile Markdown. Re-run the bounded coordinator at the completed-turn
        # lifecycle boundary so live trim does not depend on a gateway restart.
        if self._config.get("writeback_mode", _DEFAULT_WRITEBACK_MODE) == "live_overflow_trim":
            self._run_live_overflow_trim(trigger="completed_turn")
        policy = self._config.get("sync_turn_policy", _DEFAULT_SYNC_TURN_POLICY)
        live_overflow_status = self._last_status.get("live_overflow_trim")
        live_overflow_audit_id = self._last_status.get("live_overflow_audit_id")
        if policy == "off":
            return
        conn = self._open_operation_conn()
        controlled_fixture = None
        try:
            for message in messages or []:
                if isinstance(message, dict) and message.get("controlled_turn_fixture"):
                    controlled_fixture = str(message.get("controlled_turn_fixture"))
                    break
            if policy == "proposal_only":
                if controlled_fixture:
                    result = propose_completed_turn_sync(
                        conn,
                        profile_id=self._agent_identity,
                        turn_fixture_path=controlled_fixture,
                        allowed_turn_roots=self._config.get("controlled_turn_roots") or [],
                        session_id=session_id or self._session_id,
                    )
                else:
                    result = propose_completed_turn_sync(
                        conn,
                        profile_id=self._agent_identity,
                        turn_payload={
                            "user_content": user_content,
                            "assistant_content": assistant_content,
                            "messages": messages or [],
                        },
                        session_id=session_id or self._session_id,
                    )
                result.update({"provider": _PLUGIN_NAME, "sync_turn_policy": policy})
                self._last_status = result
                if live_overflow_status is not None:
                    self._last_status["live_overflow_trim"] = live_overflow_status
                if live_overflow_audit_id is not None:
                    self._last_status["live_overflow_audit_id"] = live_overflow_audit_id
                return
            status = "proposal_required" if policy == "proposal_only" else "ok"
            write_audit_event(
                conn,
                event_type="hermes.turn.sync",
                target_type="session",
                target_id=session_id or self._session_id,
                status=status,
                metadata={
                    "provider": _PLUGIN_NAME,
                    "policy": policy,
                    "user_content_chars": len(user_content or ""),
                    "assistant_content_chars": len(assistant_content or ""),
                    "messages_count": len(messages or []),
                    "controlled_fixture_present": bool(controlled_fixture),
                    "proposal_created": False,
                    "automatic_memory_promotion": False,
                    "real_profile_markdown_writeback": False,
                    "occurred_at": now_utc(),
                },
            )
            conn.commit()
        finally:
            conn.close()
        # Completed turns likewise cannot self-authorize mutation.

    def _tool_schemas_for_config(self) -> List[Dict[str, Any]]:
        recall_mode = self._config.get("recall_mode", _DEFAULT_RECALL_MODE)
        schemas: list[dict[str, Any]] = []
        if recall_mode in {"tools", "hybrid"}:
            schemas.extend([_CONTEXT_SCHEMA, _SEARCH_SCHEMA, _SOURCES_SCHEMA, _OVERFLOW_PRESSURE_SCHEMA, _OVERFLOW_PLAN_SCHEMA, _INGEST_PROFILE_SCHEMA, _SYNC_TURN_PROPOSAL_SCHEMA, _HONCHO_IMPORT_SCHEMA, _SESSION_SEARCH_IMPORT_SCHEMA, _OBSIDIAN_IMPORT_SCHEMA])
        schemas.extend([_PROPOSE_SCHEMA, _WRITEBACK_STATUS_SCHEMA])
        return schemas

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        return self._tool_schemas_for_config()

    def tool_gating_status(
        self,
        *,
        memory_enabled: bool = True,
        skip_memory: bool = False,
        enabled_toolsets: list[str] | tuple[str, ...] | None = None,
        allow_tools: list[str] | tuple[str, ...] | None = None,
        deny_tools: list[str] | tuple[str, ...] | None = None,
        existing_tool_names: list[str] | tuple[str, ...] | None = None,
        builtin_memory_tool_names: list[str] | tuple[str, ...] = ("memory",),
        honcho_tool_names: list[str] | tuple[str, ...] = ("honcho_profile", "honcho_search", "honcho_reasoning", "honcho_context", "honcho_conclude"),
    ) -> dict[str, Any]:
        """Return leak-safe memory-tool exposure status without provider side effects."""
        return evaluate_mnemoir_tool_gating(
            ToolGatingRequest(
                schemas=self._tool_schemas_for_config(),
                selected_provider_id=_PLUGIN_NAME,
                memory_enabled=memory_enabled,
                skip_memory=skip_memory,
                enabled_toolsets=enabled_toolsets,
                allow_tools=allow_tools,
                deny_tools=deny_tools,
                existing_tool_names=existing_tool_names,
                builtin_memory_tool_names=builtin_memory_tool_names,
                honcho_tool_names=honcho_tool_names,
            )
        )

    def handle_tool_call(self, tool_name: str, args: Dict[str, Any], **kwargs: Any) -> str:
        conn = None
        try:
            conn = self._open_operation_conn()
            if tool_name in {"cmc_context", "cmc_search"}:
                query = str(args.get("query") or "").strip()
                if not query:
                    return tool_error("query is required")
                packet = context_packet(conn, query, profile_id=self._agent_identity, limit=_limit(args.get("limit")), source_families=self._configured_source_families(), context_budget_chars=args.get("context_budget_chars") or self._config.get("context_budget_chars", _DEFAULT_CONTEXT_BUDGET_CHARS))
                packet["provider"] = _PLUGIN_NAME
                return _json_result(packet)
            if tool_name == "cmc_sources":
                status = provider_status(conn, profile_id=None)
                status.update({
                    "provider": _PLUGIN_NAME,
                    "selected_memory_provider": _PLUGIN_NAME,
                    "selected_provider_active": True,
                    "honcho_active": False,
                    "honcho_selected_provider": False,
                    "honcho_api_required": False,
                    "honcho_api_called": False,
                    "writeback_mode": self._config.get("writeback_mode", _DEFAULT_WRITEBACK_MODE),
                })
                return _json_result(status)
            if tool_name == "cmc_overflow_pressure":
                fixture_root = str(args.get("fixture_root") or "").strip()
                if not fixture_root:
                    return tool_error("fixture_root is required")
                status = overflow_pressure_status(self._agent_identity, fixture_root)
                status.update({
                    "provider": _PLUGIN_NAME,
                    "honcho_active": False,
                    "honcho_api_required": False,
                    "real_profile_markdown_read": False,
                    "real_profile_markdown_writeback": False,
                })
                return _json_result(status)
            if tool_name == "cmc_overflow_plan":
                plan = overflow_compaction_plan_status(conn, self._agent_identity)
                plan.update({
                    "provider": _PLUGIN_NAME,
                    "honcho_active": False,
                    "honcho_api_required": False,
                    "real_profile_markdown_read": False,
                    "real_profile_markdown_writeback": False,
                    "file_mutation_performed": False,
                })
                return _json_result(plan)
            if tool_name == "cmc_sync_turn_proposal":
                turn_fixture_path = str(args.get("turn_fixture_path") or "").strip()
                if not turn_fixture_path:
                    return tool_error("turn_fixture_path is required")
                result = propose_completed_turn_sync(
                    conn,
                    profile_id=self._agent_identity,
                    turn_fixture_path=turn_fixture_path,
                    allowed_turn_roots=self._config.get("controlled_turn_roots") or [],
                    session_id=self._session_id,
                )
                result.update({
                    "provider": _PLUGIN_NAME,
                    "honcho_active": False,
                    "honcho_api_required": False,
                    "real_profile_markdown_read": False,
                    "real_profile_markdown_writeback": False,
                    "file_mutation_performed": False,
                    "content_included": False,
                    "path_redacted": True,
                    "live_config_mutation_performed": False,
                })
                return _json_result(result)
            if tool_name == "cmc_import_session_search":
                session_fixture_path = str(args.get("session_fixture_path") or "").strip()
                if not session_fixture_path:
                    return tool_error("session_fixture_path is required")
                result = import_session_search_fixture(
                    conn,
                    profile_id=self._agent_identity,
                    session_fixture_path=session_fixture_path,
                    allowed_session_roots=self._config.get("controlled_session_search_roots") or [],
                )
                result.update({"provider": _PLUGIN_NAME, "content_included": False, "path_redacted": True, "session_search_db_read": False, "live_config_mutation_performed": False})
                return _json_result(result)
            if tool_name == "cmc_import_obsidian_vault":
                vault_root = str(args.get("vault_root") or "").strip()
                if not vault_root:
                    return tool_error("vault_root is required")
                result = import_obsidian_vault_fixture(
                    conn,
                    profile_id=self._agent_identity,
                    vault_root=vault_root,
                    allowed_vault_roots=self._config.get("controlled_obsidian_vault_roots") or [],
                    include_derived_projection=bool(args.get("include_derived_projection")),
                )
                result.update({"provider": _PLUGIN_NAME, "content_included": False, "path_redacted": True, "vault_absolute_paths_exposed": False, "live_config_mutation_performed": False})
                return _json_result(result)
            if tool_name == "cmc_import_honcho_legacy":
                honcho_fixture_path = str(args.get("honcho_fixture_path") or "").strip()
                if not honcho_fixture_path:
                    return tool_error("honcho_fixture_path is required")
                result = import_honcho_legacy_fixture(
                    conn,
                    profile_id=self._agent_identity,
                    honcho_fixture_path=honcho_fixture_path,
                    allowed_honcho_roots=self._config.get("controlled_honcho_import_roots") or [],
                )
                result.update({
                    "provider": _PLUGIN_NAME,
                    "honcho_active": False,
                    "honcho_api_required": False,
                    "honcho_api_called": False,
                    "real_profile_markdown_read": False,
                    "real_profile_markdown_writeback": False,
                    "file_mutation_performed": False,
                    "content_included": False,
                    "path_redacted": True,
                    "live_config_mutation_performed": False,
                    "provider_activation_performed": False,
                })
                return _json_result(result)
            if tool_name == "cmc_ingest_profile_markdown":
                profile_root = str(args.get("profile_root") or "").strip()
                if not profile_root:
                    return tool_error("profile_root is required")
                result = ingest_profile_markdown(
                    conn,
                    self._agent_identity,
                    profile_root,
                    allowed_profile_roots=self._config.get("controlled_profile_roots") or [],
                )
                result.update({
                    "provider": _PLUGIN_NAME,
                    "honcho_active": False,
                    "honcho_api_required": False,
                    "real_profile_markdown_read": False,
                    "real_profile_markdown_writeback": False,
                    "file_mutation_performed": False,
                    "content_included": False,
                    "path_redacted": True,
                    "live_config_mutation_performed": False,
                })
                return _json_result(result)
            if tool_name == "cmc_propose_memory":
                evidence_ids = [str(x) for x in (args.get("evidence_ids") or [])]
                source_event_ids = [str(x) for x in (args.get("source_event_ids") or [])]
                if not evidence_ids and not source_event_ids:
                    return _json_result({
                        "status": "denied",
                        "error": "missing_source_evidence",
                        "proposal_created": False,
                        "required": "evidence_ids or source_event_ids",
                    })
                result = create_proposal(
                    conn,
                    title=str(args.get("title") or "").strip(),
                    summary=str(args.get("summary") or "").strip(),
                    body=str(args.get("body") or "").strip(),
                    evidence_ids=evidence_ids,
                    source_event_ids=source_event_ids,
                    privacy_class=str(args.get("privacy_class") or "private"),
                )
                result.update({"automatic_writeback": False, "review_required": True})
                return _json_result(result)
            if tool_name == "cmc_writeback_status":
                configured_writeback_mode = self._config.get("writeback_mode", _DEFAULT_WRITEBACK_MODE)
                status = markdown_writeback_status(self._agent_identity)
                status.update({
                    "provider": _PLUGIN_NAME,
                    "writeback_mode": configured_writeback_mode,
                    "gateway_restart_required": False,
                })
                if configured_writeback_mode == "live_overflow_trim":
                    unresolved_count = conn.execute(
                        "SELECT COUNT(*) FROM writeback_operations WHERE state IN ('recovery_required','concurrent_edit_detected','blocked_target_unreachable','completed_partial','legacy_manual_recovery_required')"
                    ).fetchone()[0]
                    last_run = self._last_status.get("live_overflow_trim") or {}
                    last_mutated = int(last_run.get("mutated_file_count") or 0)
                    status.update({
                        "status": "degraded" if unresolved_count else "automatic_policy_enabled",
                        "markdown_writeback": "operator_configured_bounded_live_overflow_trim",
                        "write_authority": "operator_selected_durable_policy",
                        "automatic_policy_enabled": True,
                        "external_per_operation_approval_required": False,
                        "real_profile_markdown_writeback": True,
                        "controlled_fixture_execution_available": True,
                        "file_mutation_performed": bool(last_mutated),
                        "last_mutated_file_count": last_mutated,
                        "unresolved_operation_count": unresolved_count,
                        "provider_can_issue_internal_transaction_capability": True,
                        "non_overflow_arbitrary_writeback": "denied_or_propose_only",
                    })
                else:
                    status.update({"real_profile_markdown_writeback": False})
                return _json_result(status)
            return tool_error(f"Unknown Mnemoir memory tool: {tool_name}")
        except CurationError as exc:
            return _json_result({"status": "error", "error": str(exc), "provider": _PLUGIN_NAME})
        except Exception as exc:
            return _json_result({"status": "error", "error": type(exc).__name__, "provider": _PLUGIN_NAME})
        finally:
            if conn is not None:
                conn.close()

    def on_session_switch(self, new_session_id: str, **kwargs: Any) -> None:
        self._session_id = new_session_id or self._session_id

    def shutdown(self) -> None:
        if self._conn is not None:
            try:
                if self._conn_thread_id == threading.get_ident():
                    self._conn.close()
            finally:
                self._conn = None
                self._conn_thread_id = None


def register(ctx: Any) -> None:
    """Hermes plugin entrypoint."""
    ctx.register_memory_provider(CouncilMemoryCoreProvider())
