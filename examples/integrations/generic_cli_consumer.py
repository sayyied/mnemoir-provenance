#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mnemoir-consumer-") as temp:
        root = Path(temp)
        docs = root / "docs"
        docs.mkdir()
        (docs / "index.md").write_text("A synthetic non-Hermes host stores source-grounded memory.\n", encoding="utf-8")
        env = os.environ.copy()
        env["MNEMOIR_DB"] = str(root / "consumer.sqlite")
        env["MNEMOIR_ROOT"] = str(root)
        executable = shutil.which("mnemoir")
        cli = [executable] if executable is not None else [sys.executable, "-m", "mnemoir_provenance.cli"]
        commands = [cli + ["sources"], cli + ["ingest", "--limit", "5"], cli + ["recall", "source grounded memory", "--limit", "3"]]
        outputs = []
        for command in commands:
            proc = subprocess.run(command, env=env, text=True, capture_output=True, timeout=30)
            if proc.returncode != 0:
                print(proc.stderr, end="", file=__import__("sys").stderr)
                return proc.returncode
            outputs.append(json.loads(proc.stdout))
        result = {"status": "ok", "hermes_required": False, "cited_result_count": len(outputs[-1].get("cited_results", [])), "coverage": outputs[-1].get("source_coverage", {})}
        print(json.dumps(result, sort_keys=True))
        return 0 if result["cited_result_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
