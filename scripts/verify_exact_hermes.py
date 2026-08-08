#!/usr/bin/env python3
"""Exact-official-Hermes lifecycle proof for the generated Mnemoir candidate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile


def _tree_state(root: Path) -> dict[str, tuple[int, str]]:
    state: dict[str, tuple[int, str]] = {}
    if not root.exists():
        return state
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            data = path.read_bytes()
            state[str(path.relative_to(root))] = (
                stat.S_IMODE(path.stat().st_mode),
                hashlib.sha256(data).hexdigest(),
            )
    return state


def _proposal_count(path: Path) -> int:
    with sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM memory_proposals").fetchone()[0])


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="mnemoir-exact-hermes-") as temporary:
        root = Path(temporary)
        home = root / "primary-home"
        os.environ["HERMES_HOME"] = str(home)

        from mnemoir_provenance.plugin_install import install_hermes_plugin

        install_result = install_hermes_plugin(home)
        assert install_result["plugin_installed"] is True

        from plugins.memory import discover_memory_providers, load_memory_provider
        from agent.memory_manager import MemoryManager

        writer = load_memory_provider("mnemoir_provenance")
        assert writer is not None
        db_path = root / "primary.sqlite"
        writer.save_config(
            {
                "db_path": str(db_path),
                "mode": "proposal_only",
                "recall_mode": "hybrid",
                "sync_turn_policy": "proposal_only",
                "writeback_mode": "propose_only",
            },
            home,
        )
        config_path = home / "mnemoir_provenance.json"
        assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
        assert json.loads(config_path.read_text(encoding="utf-8"))["db_path"] == str(db_path)

        discovered = {name: available for name, _description, available in discover_memory_providers()}
        assert discovered.get("mnemoir_provenance") is True
        provider = load_memory_provider("mnemoir_provenance")
        assert provider is not None and provider.is_available()

        manager = MemoryManager()
        manager.add_provider(provider)
        manager.initialize_all(
            session_id="exact-primary",
            hermes_home=str(home),
            platform="telegram",
            agent_context="primary",
        )
        schemas = manager.get_all_tool_schemas()
        assert len(schemas) == 12
        assert len({schema["name"] for schema in schemas}) == 12
        provider_block = provider.system_prompt_block()
        assert "selected local memory provider" in provider_block
        prefetch = provider.prefetch("empty exact-Hermes recall probe")
        assert "degraded/empty" in prefetch
        prompt = manager.build_system_prompt()
        assert "selected local memory provider" in prompt
        manager.sync_all("primary marker", "source-grounded proposal marker")
        manager.shutdown_all()
        assert db_path.exists()
        assert _proposal_count(db_path) >= 1

        denied_home = root / "denied-home"
        denied_home.mkdir(mode=0o700)
        denied_db = root / "denied.sqlite"
        denied = provider.__class__()
        denied.save_config(
            {
                "db_path": str(denied_db),
                "sync_turn_policy": "proposal_only",
                "writeback_mode": "live_overflow_trim",
            },
            denied_home,
        )
        before = _tree_state(root)
        denied_manager = MemoryManager()
        denied_manager.add_provider(denied)
        denied_manager.initialize_all(
            session_id="exact-cron",
            hermes_home=str(denied_home),
            platform="cron",
            agent_context="primary",
        )
        assert "disabled" in denied_manager.build_system_prompt().lower()
        denied_manager.prefetch_all("cron marker")
        denied_manager.sync_all("cron marker", "must not persist")
        for schema in denied_manager.get_all_tool_schemas():
            result = denied_manager.handle_tool_call(schema["name"], {})
            payload = json.loads(result) if isinstance(result, str) else result
            assert payload["error"] == "execution_context_denied"
        denied_manager.shutdown_all()
        after = _tree_state(root)
        assert after == before
        assert not denied_db.exists()

    print("exact-official-Hermes lifecycle proof: PASS")


if __name__ == "__main__":
    main()
