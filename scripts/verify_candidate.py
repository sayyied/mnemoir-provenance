#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []
checks: dict[str, object] = {}
version = "0.2.0"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def png_dimensions(path: Path) -> tuple[int, int] | None:
    data = path.read_bytes()[:24]
    if len(data) != 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        return None
    return struct.unpack(">II", data[16:24])


if version not in (ROOT / "pyproject.toml").read_text(encoding="utf-8"):
    errors.append("version-mismatch")

for required in [
    "README.md",
    "SECURITY.md",
    "SOURCE_PROVENANCE.json",
    "PUBLIC_FILE_MANIFEST.json",
    "docs/index.md",
    "src/mnemoir_provenance/resources/0001_initial_schema.sql",
]:
    if not (ROOT / required).is_file():
        errors.append(f"missing:{required}")

manifest_path = ROOT / "PUBLIC_FILE_MANIFEST.json"
provenance_path = ROOT / "SOURCE_PROVENANCE.json"
expected: dict[str, dict[str, object]] = {}
if manifest_path.is_file():
    try:
        rows = json.loads(manifest_path.read_text(encoding="utf-8"))["files"]
        for row in rows:
            rel = str(row["path"])
            if rel in expected:
                errors.append(f"manifest-duplicate:{rel}")
            expected[rel] = row
        checks["manifest_entries"] = len(rows)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"manifest-invalid:{exc}")

for rel, row in expected.items():
    path = ROOT / rel
    if path.is_symlink() or not path.is_file():
        errors.append(f"manifest-file-invalid:{rel}")
        continue
    if path.stat().st_size != int(row["size"]):
        errors.append(f"manifest-size:{rel}")
    if sha256(path) != str(row["sha256"]):
        errors.append(f"manifest-sha256:{rel}")
    actual_mode = f"{stat.S_IMODE(path.stat().st_mode):04o}"
    if actual_mode != str(row["mode"]):
        errors.append(f"manifest-mode:{rel}:{actual_mode}")

allowed_envelopes = {"PUBLIC_FILE_MANIFEST.json", "SOURCE_PROVENANCE.json"}
actual = {
    path.relative_to(ROOT).as_posix()
    for path in ROOT.rglob("*")
    if ".git" not in path.relative_to(ROOT).parts and (path.is_file() or path.is_symlink())
}
expected_output = set(expected) | allowed_envelopes
for rel in sorted(actual - expected_output):
    errors.append(f"unexpected-file:{rel}")
for rel in sorted(expected_output - actual):
    errors.append(f"output-missing:{rel}")
checks["output_files"] = len(actual)

if provenance_path.is_file() and manifest_path.is_file():
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        if provenance.get("public_tree_manifest_sha256") != sha256(manifest_path):
            errors.append("provenance-public-manifest-sha256")
        if provenance.get("version") != version:
            errors.append("provenance-version")
    except json.JSONDecodeError as exc:
        errors.append(f"provenance-invalid:{exc}")

for doc in ROOT.rglob("*.md"):
    if ".git" in doc.relative_to(ROOT).parts:
        continue
    text = doc.read_text(encoding="utf-8")
    targets = re.findall(r"\[[^]]+\]\(([^)]+)\)", text)
    targets += re.findall(r'<img[^>]+src="([^"]+)"', text)
    for target in targets:
        if "://" in target or target.startswith(("#", "mailto:")):
            continue
        relative = target.split("#", 1)[0]
        if relative and not (doc.parent / relative).resolve().exists():
            errors.append(f"broken-link:{doc.relative_to(ROOT)}:{target}")

screenshot_manifest_path = ROOT / "assets/screenshots/manifest.json"
if screenshot_manifest_path.is_file():
    try:
        screenshot_manifest = json.loads(screenshot_manifest_path.read_text(encoding="utf-8"))
        for row in screenshot_manifest.get("screenshots", []):
            rel = str(row["path"])
            path = ROOT / rel
            if not path.is_file() or path.is_symlink():
                errors.append(f"screenshot-missing:{rel}")
                continue
            if sha256(path) != row.get("sha256"):
                errors.append(f"screenshot-sha256:{rel}")
            dimensions = png_dimensions(path)
            expected_dimensions = tuple(int(value) for value in str(row["pixel_dimensions"]).split("x"))
            if dimensions != expected_dimensions:
                errors.append(f"screenshot-dimensions:{rel}")
        for rel, expected_hash in screenshot_manifest.get("ui_assets", {}).items():
            path = ROOT / rel
            if not path.is_file() or sha256(path) != expected_hash:
                errors.append(f"ui-asset-sha256:{rel}")
        checks["screenshots"] = len(screenshot_manifest.get("screenshots", []))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"screenshot-manifest-invalid:{exc}")

env = os.environ.copy()
env["PYTHONDONTWRITEBYTECODE"] = "1"
env["PYTHONPATH"] = str(ROOT / "src")
proc = subprocess.run(
    [sys.executable, "-m", "mnemoir_provenance.cli", "--help"],
    cwd=ROOT,
    env=env,
    text=True,
    capture_output=True,
)
if proc.returncode != 0 or "mnemoir" not in proc.stdout.lower():
    errors.append("cli-help")

print(json.dumps({"status": "ok" if not errors else "error", "errors": errors, "checks": checks}, sort_keys=True))
raise SystemExit(0 if not errors else 1)
