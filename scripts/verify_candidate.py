#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
errors = []
version = "0.2.0-rc.1"
if version not in (ROOT / "pyproject.toml").read_text():
    errors.append("version mismatch")
for required in ["README.md", "SECURITY.md", "SOURCE_PROVENANCE.json", "docs/index.md", "src/mnemoir_provenance/resources/0001_initial_schema.sql"]:
    if not (ROOT / required).is_file():
        errors.append(f"missing:{required}")
for doc in ROOT.rglob("*.md"):
    text = doc.read_text(encoding="utf-8")
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
        if "://" in target or target.startswith("#"):
            continue
        resolved = (doc.parent / target.split("#", 1)[0]).resolve()
        if not resolved.exists():
            errors.append(f"broken-link:{doc.relative_to(ROOT)}:{target}")
proc = subprocess.run([sys.executable, "-m", "mnemoir_provenance.cli", "--help"], cwd=ROOT, text=True, capture_output=True)
if proc.returncode != 0 or "mnemoir" not in proc.stdout.lower():
    errors.append("cli help failed")
print(json.dumps({"status": "ok" if not errors else "error", "errors": errors}, sort_keys=True))
raise SystemExit(0 if not errors else 1)
