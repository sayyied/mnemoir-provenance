import importlib
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType

from mnemoir_provenance.db import connect, initialize_database
from mnemoir_provenance.scope import decide_visibility
from mnemoir_provenance.source_adapters import import_session_search_fixture

ROOT = Path(__file__).resolve().parents[1]


def test_controlled_session_export_and_scope_boundary(tmp_path):
    fixture = tmp_path / "turns.json"
    fixture.write_text(json.dumps({"messages": [{"id": "m1", "role": "user", "content": "Synthetic harness remembers the selected blue theme.", "privacy_class": "private"}]}), encoding="utf-8")
    with connect(tmp_path / "db.sqlite") as conn:
        initialize_database(conn)
        result = import_session_search_fixture(conn, profile_id="demo", session_fixture_path=fixture)
        assert result["status"] == "ok"
        assert result["records_imported"] == 1
        assert result["session_search_db_read"] is False
        assert str(tmp_path) not in json.dumps(result)


def test_python_quickstart_owns_database_source_and_empty_path():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "examples/quickstart/python_quickstart.py")],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["status"] == "ok"
    assert payload["hermes_required"] is False
    assert payload["database_owned_by_host"] is True
    assert payload["source_scope_explicit"] is True
    assert payload["cited_result_count"] >= 1
    assert payload["empty_result_count"] == 0


def test_non_hermes_consumer_script_has_no_hermes_dependency():
    proc = subprocess.run([sys.executable, str(ROOT / "examples/integrations/generic_cli_consumer.py"), "--self-test"], cwd=ROOT, text=True, capture_output=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["status"] == "ok"
    assert payload["hermes_required"] is False
    assert payload["database_owned_by_host"] is True
    assert payload["source_scope_explicit"] is True
    assert payload["timeout_seconds"] == 30
    assert payload["cited_result_count"] >= 1
    assert payload["empty_result_count"] == 0


def test_host_boundary_scope_denial_is_explicit_and_leak_safe(seeded_db):
    with connect(seeded_db) as conn:
        initialize_database(conn)
        denied = decide_visibility(
            conn,
            actor_id="unknown_external_actor",
            target_type="source",
            target_id="demo_source",
            permission="read",
        )
        assert denied["status"] == "unauthorized"
        assert denied["reason"] == "requesting_actor_not_found"
        assert denied["profile_internals_exposed"] is False
        assert "/home/" not in json.dumps(denied)


def _insert_writeback(conn, operation_id, *, profile_id, state, target="target", operation_type="live_overflow_trim"):
    authorization_id = f"auth-{operation_id}"
    created_at = "2026-01-01T00:00:00Z"
    conn.execute(
        "INSERT INTO writeback_authorizations(authorization_id,operation_id,nonce_hash,capability_hash,profile_id,target_path_hash,allowed_root_hash,expected_before_hash,operation_type,policy_version,approving_actor,issued_at,expires_at,consumed_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (authorization_id, operation_id, f"nonce-{operation_id}", f"capability-{operation_id}", profile_id, target, "root", "before", operation_type, "test", "reviewer", created_at, "2099-01-01T00:00:00Z", created_at, created_at),
    )
    conn.execute(
        "INSERT INTO writeback_operations(operation_id,authorization_id,profile_id,target_path_hash,allowed_root_hash,expected_before_hash,policy_version,operation_type,state,evidence_state,audit_state,created_at,updated_at,completed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (operation_id, authorization_id, profile_id, target, "root", "before", "test", operation_type, state, "committed", "committed", created_at, created_at, created_at),
    )
    conn.commit()


def test_writeback_status_distinguishes_superseded_partials_from_hard_recovery(tmp_path, monkeypatch):
    db_path = tmp_path / "mnemoir.sqlite"
    with connect(db_path) as conn:
        initialize_database(conn)
        _insert_writeback(conn, "partial", profile_id="demo", state="completed_partial")
        _insert_writeback(conn, "success", profile_id="demo", state="completed")
        _insert_writeback(conn, "other-profile", profile_id="other", state="completed_partial")

    (tmp_path / "mnemoir_provenance.json").write_text(
        json.dumps({"db_path": str(db_path), "writeback_mode": "live_overflow_trim"}),
        encoding="utf-8",
    )
    agent_module = ModuleType("agent")
    agent_module.__path__ = []
    memory_provider_module = ModuleType("agent.memory_provider")
    setattr(memory_provider_module, "MemoryProvider", type("MemoryProvider", (), {}))
    tools_module = ModuleType("tools")
    tools_module.__path__ = []
    registry_module = ModuleType("tools.registry")
    setattr(registry_module, "tool_error", lambda message: {"status": "error", "error": message})
    monkeypatch.setitem(sys.modules, "agent", agent_module)
    monkeypatch.setitem(sys.modules, "agent.memory_provider", memory_provider_module)
    monkeypatch.setitem(sys.modules, "tools", tools_module)
    monkeypatch.setitem(sys.modules, "tools.registry", registry_module)
    provider_module = importlib.import_module("mnemoir_provenance.hermes_plugin.provider")
    provider = provider_module.CouncilMemoryCoreProvider()
    provider.initialize("public-regression", hermes_home=tmp_path, agent_identity="demo")
    status = json.loads(provider.handle_tool_call("cmc_writeback_status", {}))
    assert status["unresolved_operation_count"] == 0
    assert status["historical_partial_operation_count"] == 1

    with connect(db_path) as conn:
        _insert_writeback(conn, "hard", profile_id="demo", state="recovery_required")
        _insert_writeback(conn, "later-success", profile_id="demo", state="completed")
    status = json.loads(provider.handle_tool_call("cmc_writeback_status", {}))
    assert status["status"] == "degraded"
    assert status["unresolved_operation_count"] == 1
