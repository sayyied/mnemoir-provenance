from pathlib import Path

import pytest

from mnemoir_provenance.db import connect, initialize_database, sha256_text
from mnemoir_provenance.live_overflow import LiveOverflowError, create_writeback_authorization, execute_writeback, request_from_authorization, rollback_writeback
from mnemoir_provenance.overflow_policy import compute_markdown_pressure


def fixture_target(tmp_path: Path):
    root = tmp_path / "working-memory"
    root.mkdir()
    target = root / "MEMORY.md"
    target.write_text("\n§\n".join(f"synthetic block {i} " + "x" * 380 for i in range(8)), encoding="utf-8")
    return root, target


def test_pressure_proposal_writeback_readback_and_rollback(tmp_path):
    root, target = fixture_target(tmp_path)
    before = target.read_text(encoding="utf-8")
    pressure = compute_markdown_pressure(file_name="MEMORY.md", text=before, profile_id="demo")
    assert pressure["trigger_state"] is True
    db = tmp_path / "db.sqlite"
    with connect(db) as conn:
        initialize_database(conn)
        auth = create_writeback_authorization(conn, operation_id="trim-demo", profile_id="demo", target_path=target, allowed_root=root, expected_before_hash=sha256_text(before), approving_actor="external-reviewer")
        result = execute_writeback(conn, request_from_authorization(auth), auth, backup_root=tmp_path / "private")
        assert result["state"] == "completed"
        after = target.read_text(encoding="utf-8")
        assert len(after) < len(before)
        rollback_auth = create_writeback_authorization(conn, operation_id="rollback-demo", profile_id="demo", target_path=target, allowed_root=root, expected_before_hash=sha256_text(after), approving_actor="external-reviewer", operation_type="rollback", proposal_id="trim-demo")
        rolled = rollback_writeback(conn, "trim-demo", request_from_authorization(rollback_auth), rollback_auth, backup_root=tmp_path / "private")
        assert rolled["state"] == "rolled_back"
        assert target.read_text(encoding="utf-8") == before


def test_stale_hash_and_symlink_fail_closed(tmp_path):
    root, target = fixture_target(tmp_path)
    with connect(tmp_path / "db.sqlite") as conn:
        initialize_database(conn)
        auth = create_writeback_authorization(conn, operation_id="stale", profile_id="demo", target_path=target, allowed_root=root, expected_before_hash=sha256_text(target.read_text()), approving_actor="external-reviewer")
        target.write_text(target.read_text() + "\nchanged", encoding="utf-8")
        result = execute_writeback(conn, request_from_authorization(auth), auth, backup_root=tmp_path / "private")
        assert result["state"] == "concurrent_edit_detected"
    real = tmp_path / "real"
    real.write_text("x")
    link = root / "USER.md"
    link.symlink_to(real)
    with connect(tmp_path / "other.sqlite") as conn:
        initialize_database(conn)
        with pytest.raises(LiveOverflowError):
            create_writeback_authorization(conn, operation_id="link", profile_id="demo", target_path=link, allowed_root=root, expected_before_hash=sha256_text("x"), approving_actor="external-reviewer")
