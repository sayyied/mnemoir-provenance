# Mnemoir Provenance

**Agent memory that can show where it came from — and what changed.**

Mnemoir Provenance is a local Python and SQLite memory layer for agents, assistants, and long-running AI systems. It ingests explicitly controlled sources, returns recall with citations and source-coverage status, and keeps durable memory changes behind a reviewable, versioned lifecycle.

When evidence is unavailable, Mnemoir keeps that gap visible instead of quietly substituting an uncited result.

**0.2.1 · Beta · Python 3.11–3.12 supported · MIT · Hermes optional**

- [Quick start](#quick-start)
- [How it works](#from-source-to-recall)
- [Documentation](docs/index.md)

## Memory should not ask you to trust it blindly

Persistent agent memory creates difficult questions:

- Where did this claim come from?
- Which configured sources were unavailable when it was recalled?
- Who or what approved it as durable memory?
- What happened when it was corrected, deactivated, or rolled back?

Mnemoir keeps those questions attached to the record. Recall can include source identity, a safe pointer, a content hash, observation time, and source-coverage status. Observations do not become durable memories automatically. Normal revisions add version history instead of silently overwriting the prior record.

> **Citations expose lineage, not truth.** Mnemoir shows which material supported a result; the operator remains responsible for source authority, correctness, and interpretation.

## What changes with Mnemoir

- **Recall has evidence attached.** Eligible results carry pointers and hashes back to supporting material instead of returning an origin-free memory.
- **Missing sources stay visible.** Responses report which configured sources were searched and which were missing or degraded. A successful result does not conceal impaired coverage.
- **Empty recall stays empty.** No eligible match can produce an abstaining or empty response rather than an uncited fallback. Empty recall is not a claim that something is false.
- **Durable memory is a decision.** Source observations can become proposals; review, approval, writing, read-back, revision, tombstone, and rollback remain separate recorded operations.

## See cited recall

<p align="center">
  <img src="assets/screenshots/recall-citation-detail.png" width="320" alt="A Mnemoir mobile cited recall result with the complete quote, source identity, pointer, observation time, health, and eligibility">
</p>

<p align="center">
  <img src="assets/screenshots/recall-coverage-detail.png" width="320" alt="Mnemoir mobile source coverage decision showing five searched sources and one degraded or missing source">
</p>

*Cited recall keeps the supported statement, source pointer, eligibility, and configured-source coverage together. These native 320px crops preserve the mobile UI's evidence text without shrinking a wider screenshot.*

<details>
<summary><strong>See the complete Recall page and local workbench</strong></summary>

![Complete Mnemoir Recall page with three citations](assets/screenshots/recall-desktop.png)

![Mnemoir local operator workbench showing an approval-needed attention item](assets/screenshots/home-desktop.png)

*The local workbench brings decisions that need judgment to the front while keeping routine system posture secondary.*

</details>

*Screenshots use deterministic synthetic records and contain no private profile data. The selected image/UI hashes, dimensions, states, and crop coordinates are recorded in the [screenshot manifest](assets/screenshots/manifest.json). The full runtime capture bundle is not included in this public mirror.*

## From source to recall

Mnemoir separates records that are often collapsed into one opaque “memory” object:

1. **Observe.** Register a controlled source and ingest source-identified, hashed observations. An observation is not automatically accepted memory.
2. **Recall.** Return eligible evidence with citations, query identity, audit state, and the health of configured sources.
3. **Decide.** Turn supported material into a proposal; record an attributable approval, edit, or rejection. Hosts may impose stricter reviewer policy.
4. **Preserve change.** Write an approved record to canonical SQLite, read it back, and retain application-level history through normal revisions, tombstones, and rollback.

**Canonical boundary:** SQLite remains authoritative. Markdown views are derived, and working-memory changes require a separately authorized adapter.

## Quick start

### Install from PyPI (normal user path)

| Surface | Exact identity |
|---|---|
| PyPI distribution | `mnemoir-provenance` |
| Command | `mnemoir` |
| Python import | `mnemoir_provenance` |
| Hermes provider | `mnemoir_provenance` |

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install mnemoir-provenance
python -m pip check
python -c "import mnemoir_provenance; print(mnemoir_provenance.__version__)"
mnemoir --version
```

Use the command above for a first installation. To upgrade an existing Mnemoir installation to the newest available release, add pip's `--upgrade` flag:

```bash
python -m pip install --upgrade mnemoir-provenance
```

For a reproducible installation of this exact release, pin the version; `--upgrade` is unnecessary with the exact pin:

```bash
python -m pip install 'mnemoir-provenance==0.2.1'
```

Run the standalone CLI flow directly from the installed package:

```bash
export MNEMOIR_ROOT="$PWD/example-source"
export MNEMOIR_DB="$PWD/mnemoir.sqlite"
mkdir -p "$MNEMOIR_ROOT/docs"
printf '%s\n' 'Synthetic evidence: Mnemoir returns cited local recall.' > "$MNEMOIR_ROOT/docs/index.md"
mnemoir sources
mnemoir ingest --limit 5
mnemoir recall "cited local recall" --limit 3
```

A repository checkout also includes `examples/quickstart/python_quickstart.py`; cloning the repository is not required for the CLI flow above.

Expected recall contains `cited_results`, safe source pointers and content hashes. An unrelated query may return zero results; a missing configured source returns explicit degraded coverage rather than uncited fallback.

### Development checkout (contributors only)

```bash
git clone https://github.com/sayyied/mnemoir-provenance.git
cd mnemoir-provenance
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test]'
python -m pytest -q
```

Clone/editable installation is not required for normal use.

## Optional Hermes reference adapter

Hermes and Mnemoir must be importable in the **same Python runtime**. In a fresh shared environment:

```bash
python -m pip install 'mnemoir-provenance[hermes]'
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
mnemoir plugin install --hermes-home "$HERMES_HOME"
mnemoir plugin status --hermes-home "$HERMES_HOME" --hermes-python "$(command -v python)"
```

For an existing Hermes installation, use the Python interpreter that owns its `hermes` command:

```bash
HERMES_PYTHON=/path/to/hermes/environment/bin/python
"$HERMES_PYTHON" -m pip install 'mnemoir-provenance[hermes]'
"$(dirname "$HERMES_PYTHON")/mnemoir" plugin install --hermes-home "$HERMES_HOME"
```

That command adds Mnemoir to the Hermes environment when it is absent. If Mnemoir is already installed there and you intend to update it, use `"$HERMES_PYTHON" -m pip install --upgrade 'mnemoir-provenance[hermes]'` instead.

The explicit installer copies the plugin and creates only the default profile-scoped storage parent at restrictive mode `0700`. It does **not** select the provider, edit Hermes configuration, restart a gateway, ingest sources, promote memory, or enable writeback. Provider selection is separate and explicit:

```bash
hermes memory setup mnemoir_provenance
hermes memory status
```

`hermes memory status` is authoritative for exclusive memory-provider selection. `hermes plugins list` describes general plugin enablement and may not reflect memory-provider selection. Start a new Hermes process/session through your normal operational procedure after selection; do not assume a running gateway reloads configuration.

A fresh selected provider is intentionally empty/degraded because `ingest_on_start=false`. To prove one controlled source without touching a live profile:

```bash
mnemoir plugin bootstrap-profile \
  --hermes-home "$HERMES_HOME" \
  --profile-root /path/to/controlled-fixture \
  --profile-id demo-profile \
  --verify-query "distinct phrase in the fixture"
```

For v0.2.1, the controlled fixture must contain both immediate non-symlink `MEMORY.md` and `USER.md` inputs; either file may be minimal, but an absent configured source is reported as degraded and the bootstrap fails closed. Output validates against [`plugin-bootstrap-profile-result.schema.json`](docs/reference/schemas/plugin-bootstrap-profile-result.schema.json). It reports counts, citations and side-effect booleans—not source text or absolute paths. `bootstrap_no_cited_match` preserves committed idempotent evidence; rerun with a query matching the controlled fixture. The command never promotes durable memory or performs writeback.

### Disable, rollback and retain data

```bash
hermes memory off
hermes memory status
```

Deselecting the provider or removing its copied plugin does not delete the SQLite database. Back up and retain the operator-owned DB according to policy before removing it manually. The public provider `mnemoir_provenance` does not silently replace the historical private provider `council_memory_core`, rewrite selection, or copy/rename an old DB. Deliberate migration requires an SQLite-consistent backup, an explicit target DB, count/hash/read-back checks, and keeping the old provider/DB intact until rollback is no longer needed.

## Generic Python or JSON-CLI hosts

Hermes is not required. Hosts may use the in-process Python API or invoke `mnemoir` as a local JSON subprocess. The host owns database location, source authority, tenant/profile/project/session scope mapping, prompt rendering, approvals, retention, backup, concurrency, timeouts, cancellation, and teardown. See [Python integration](docs/guides/integrate-python.md), [JSON CLI integration](docs/guides/integrate-cli-json.md), and the tested [generic consumer](examples/integrations/generic_cli_consumer.py). No universal auto-attachment protocol or untested named-harness compatibility is claimed.

## Choose your integration

- **[Python API](docs/guides/integrate-python.md)** — direct in-process control for Python agents and assistants.
- **[JSON CLI](docs/guides/integrate-cli-json.md)** — language-neutral subprocess integration with machine-readable responses and exit codes.
- **[Generic host example](examples/integrations/generic_cli_consumer.py)** — tested proof that the core works without Hermes imports.
- **Local workbench** — run `mnemoir ui` to inspect recall, proposals, approvals, receipts, and system posture over loopback.
- **[Hermes reference adapter](docs/guides/integrate-hermes.md)** — optional profile-scoped context and recall; Hermes is not required by the core.

## Optional capabilities

The primary product is source-grounded recall and controlled memory lifecycle. Advanced operators can add:

- **Retrieval intelligence:** [adaptive scoring](docs/concepts/adaptive-thermal-scoring.md) and offline memory-model experiments that change ordering—not source authority.
- **Coordination:** [multi-actor records](docs/concepts/multi-agent-council-records.md) and [bounded local autonomy](docs/concepts/bounded-autonomy.md) with attributable decisions, budgets, pause/kill controls, and receipts.
- **Operations:** authorized [overflow/writeback](docs/concepts/overflow-trim-and-writeback.md), controlled import from supplied exports, and [derived Markdown/Obsidian views](docs/guides/project-to-obsidian.md) that never replace canonical SQLite.

## Trust boundaries

- **Provenance is not truth.** Citations and hashes identify supporting bytes and lineage; they do not prove correctness, completeness, or authority.
- **Coverage is configured-source coverage.** It does not prove every relevant source was registered, fully ingested, current, or correct.
- **Local does not mean encrypted.** SQLite, imported content, projections, and recovery backups may contain sensitive plaintext. Operators own filesystem permissions, backup policy, retention, and deletion.
- **Hosts still enforce user policy.** Generic local retrieval assumes a trusted operator boundary. Host applications remain responsible for authorization, scope mapping, privacy rendering, and model-facing presentation.
- **Installation starts no runtime.** The package enables no telemetry, daemon, hosted service, or network listener merely by being installed. `mnemoir ui` explicitly starts a loopback listener.
- **Mutation is explicit.** Observations are not promoted automatically, and live working-memory writeback is off until a supported host adapter and durable policy are configured.

Mnemoir is not a truth oracle, a hosted memory API, an implicit private-file crawler, a general autonomous tool executor, encrypted storage, or an operating-system sandbox.

Read [SECURITY.md](SECURITY.md), the [security model](docs/operations/security-model.md), and [privacy and data handling](docs/operations/privacy-and-data-handling.md) before deployment.

## Project status

The repository currently identifies as Mnemoir Provenance 0.2.1 and is classified **Beta**. Python 3.11 and 3.12 are the tested and supported targets. Package metadata permits installation on newer Python 3 versions, but this version makes no support claim beyond 3.12. Linux is the tested and supported candidate environment. The package is MIT licensed.

Mnemoir Provenance is an independent open-source project and is not affiliated with other projects using similar names.

## Documentation

- [Installation](docs/getting-started/installation.md)
- [Mental model](docs/concepts/mental-model.md)
- [Source grounding and provenance](docs/concepts/source-grounding-and-provenance.md)
- [Memory lifecycle and curation](docs/concepts/memory-lifecycle-and-curation.md)
- [Retrieval and context packing](docs/concepts/retrieval-and-context-packing.md)
- [CLI reference](docs/reference/cli.md)
- [Python API reference](docs/reference/python-api.md)
- [Operations](docs/operations/local-deployment.md)
- [Troubleshooting](docs/troubleshooting/index.md)
- [Contributing](CONTRIBUTING.md)

## License

[MIT](LICENSE)
