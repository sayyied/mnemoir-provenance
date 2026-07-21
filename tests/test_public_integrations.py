import json
from pathlib import Path
import subprocess
import sys

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
