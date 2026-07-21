from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import stat

from jsonschema import Draft202012Validator

from mnemoir_provenance.plugin_install import install_hermes_plugin
from mnemoir_provenance.plugin_onboarding import bootstrap_profile, plugin_status

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads(
    (ROOT / "docs/reference/schemas/plugin-bootstrap-profile-result.schema.json").read_text(
        encoding="utf-8"
    )
)
VALIDATOR = Draft202012Validator(SCHEMA)


def _fixture(path: Path) -> None:
    path.mkdir()
    (path / "MEMORY.md").write_text(
        "Controlled synthetic evidence: cobalt cards preserve cited lineage.\n",
        encoding="utf-8",
    )
    (path / "USER.md").write_text(
        "Controlled synthetic user fact: empty recall stays explicit.\n",
        encoding="utf-8",
    )


def test_explicit_install_bootstraps_only_restrictive_default_parent(tmp_path: Path) -> None:
    home = tmp_path / "hermes-home"
    result = install_hermes_plugin(home)
    parent = home / "mnemoir-provenance"

    assert parent.is_dir()
    assert stat.S_IMODE(parent.stat().st_mode) == 0o700
    assert result["storage_parent_ready"] is True
    assert result["storage_parent_created"] is True
    assert result["config_mutated"] is False
    assert result["provider_selected"] is False
    assert result["gateway_restart_performed"] is False
    assert result["ingestion_performed"] is False
    assert result["promotion_performed"] is False
    assert result["writeback_performed"] is False
    assert not (home / "config.yaml").exists()
    assert not list(parent.glob("*.sqlite"))

    replay = install_hermes_plugin(home)
    assert replay["storage_parent_created"] is False
    assert replay["idempotent_replay"] is True


def test_bootstrap_profile_success_replay_no_promotion_or_writeback(tmp_path: Path) -> None:
    home = tmp_path / "hermes-home"
    install_hermes_plugin(home)
    profile = tmp_path / "controlled-profile"
    _fixture(profile)
    before = {name: (profile / name).read_bytes() for name in ("MEMORY.md", "USER.md")}

    code, result = bootstrap_profile(
        hermes_home=home,
        profile_root=profile,
        profile_id="demo-profile",
        verify_query="cobalt cards cited lineage",
        require_hermes_runtime=False,
    )
    VALIDATOR.validate(result)
    assert code == 0
    assert result["status"] == "ok"
    assert result["counts"]["recall_result_count"] >= 1
    assert result["citations"]
    assert result["promotion_performed"] is False
    assert result["writeback_performed"] is False
    assert {name: (profile / name).read_bytes() for name in before} == before

    db = home / "mnemoir-provenance" / "mnemoir.sqlite"
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM memory_proposals").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0] == 0

    replay_code, replay = bootstrap_profile(
        hermes_home=home,
        profile_root=profile,
        profile_id="demo-profile",
        verify_query="cobalt cards cited lineage",
        require_hermes_runtime=False,
    )
    VALIDATOR.validate(replay)
    assert replay_code == 0
    assert replay["idempotent_replay"] is True


def test_bootstrap_no_cited_match_and_preflight_failures_validate(tmp_path: Path) -> None:
    home = tmp_path / "hermes-home"
    install_hermes_plugin(home)
    profile = tmp_path / "controlled-profile"
    _fixture(profile)

    code, no_match = bootstrap_profile(
        hermes_home=home,
        profile_root=profile,
        profile_id="demo-profile",
        verify_query="zzzz-no-overlap-9f76b2",
        require_hermes_runtime=False,
    )
    VALIDATOR.validate(no_match)
    assert code == 4
    assert no_match["error"]["code"] == "bootstrap_no_cited_match"
    assert no_match["ingest_committed"] is True

    code, denied = bootstrap_profile(
        hermes_home=home,
        profile_root=profile,
        profile_id="unsafe/profile",
        verify_query="cobalt",
        require_hermes_runtime=False,
    )
    VALIDATOR.validate(denied)
    assert code == 2
    assert denied["error"]["code"] == "profile_scope_invalid"
    assert denied["profile_id"] is None


def test_wrong_runtime_status_is_actionable_and_non_mutating(tmp_path: Path) -> None:
    home = tmp_path / "hermes-home"
    install_hermes_plugin(home)
    result = plugin_status(home, hermes_python=tmp_path / "missing-python")
    assert result["status"] == "error"
    assert result["error"]["code"] == "package_not_importable_in_hermes_runtime"
    assert "-m pip install" in result["error"]["message"]
    assert result["config_mutated"] is False
    assert result["provider_selected"] is False
    assert result["gateway_restart_performed"] is False
