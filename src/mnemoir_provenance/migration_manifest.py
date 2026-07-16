"""compat 15.1A migration source manifest and reconciliation helpers.

The helpers in this module are deliberately data-plane conservative: callers pass
controlled/exported counts and import summaries, and the functions return only
hashes/counts/verdicts. They do not acquire exports, call Honcho, read live Hermes
profiles, mutate provider configuration, activate compat 15.2, delete Honcho data,
or promote migrated rows into canonical memories.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from .db import json_dumps, now_utc, sha256_text, stable_id

VERDICTS = ("PASS", "PARTIAL", "BLOCKED", "NO-GO")
VERDICT_RANK = {"PASS": 0, "PARTIAL": 1, "BLOCKED": 2, "NO-GO": 3}

REQUIRED_SOURCE_FAMILIES = (
    "honcho_messages",
    "honcho_conclusions_inferences",
    "honcho_peer_cards",
    "honcho_summaries",
    "hermes_memory_md",
    "hermes_user_md",
    "session_search_export",
    "obsidian_vault_export",
    "seven_profile_memory_sources",
    "generated_scale_fixture",
)

SUPPORTED_SOURCE_FAMILIES = set(REQUIRED_SOURCE_FAMILIES) | {
    "honcho_export",
    "honcho_snapshot",
    "council_profile_memory",
    "other_authorized_export",
}

REQUIRED_ROW_KEYS = (
    "source_family",
    "profile_id",
    "acquisition_authority",
    "acquisition_method",
    "export_timestamp",
    "snapshot_hash",
    "expected_counts_by_record_class",
    "observed_counts_by_record_class",
    "imported_counts_by_cmc_table",
    "canonical_promotion_count",
)

_IMPORT_REQUIRED_TABLES = ("raw_events", "evidence_items", "provenance_edges")
_FORBIDDEN_ACTION_FLAGS = {
    "honcho_api_called",
    "live_profile_markdown_read",
    "live_profile_markdown_writeback",
    "live_config_mutation_performed",
    "gateway_restart_performed",
    "cron_systemd_autostart_mutated",
    "compat_15_2_activation_performed",
    "honcho_deletion_performed",
}


class MigrationManifestError(ValueError):
    """Fail-closed manifest validation error."""


def _count_sum(value: dict[str, Any] | None) -> int:
    total = 0
    for item in (value or {}).values():
        try:
            total += int(item)
        except (TypeError, ValueError):
            continue
    return total


def _clean_counts(value: dict[str, Any] | None) -> dict[str, int]:
    cleaned: dict[str, int] = {}
    for key, count in (value or {}).items():
        if not key:
            continue
        try:
            parsed = int(count)
        except (TypeError, ValueError) as exc:
            raise MigrationManifestError("manifest_count_not_integer") from exc
        if parsed < 0:
            raise MigrationManifestError("manifest_count_negative")
        cleaned[str(key)] = parsed
    return cleaned


def _hash_ref(value: str | None) -> str:
    return sha256_text(value or "redacted")


def _worst(verdicts: Iterable[str]) -> str:
    return max(verdicts or ["PASS"], key=lambda item: VERDICT_RANK[item])


@dataclass(frozen=True)
class MigrationManifestRow:
    """One source-family/profile/export row in the compat 15.1A manifest."""

    source_family: str
    profile_id: str
    acquisition_authority: str
    acquisition_method: str
    export_timestamp: str | None = None
    snapshot_hash: str | None = None
    expected_counts_by_record_class: dict[str, int] = field(default_factory=dict)
    observed_counts_by_record_class: dict[str, int] = field(default_factory=dict)
    imported_counts_by_mnemoir_table: dict[str, int] = field(default_factory=dict)
    council_member: str | None = None
    workspace_label: str | None = None
    authorization_ref: str | None = None
    skipped_counts_by_reason: dict[str, int] = field(default_factory=dict)
    degraded_counts_by_reason: dict[str, int] = field(default_factory=dict)
    malformed_count: int = 0
    unsupported_count: int = 0
    duplicate_count: int = 0
    compacted_count: int = 0
    proposal_staged_count: int = 0
    evidence_only_count: int = 0
    canonical_promotion_count: int = 0
    explicit_exclusions: list[str] = field(default_factory=list)
    deferred_sources: list[str] = field(default_factory=list)
    proposal_policy: str = "review_required_no_silent_promotion"
    content_included: bool = False
    path_redacted: bool = True

    def to_dict(self) -> dict[str, Any]:
        row = {
            "row_id": stable_id("migration_manifest_row", self.source_family, self.profile_id, self.snapshot_hash or "deferred"),
            "source_family": self.source_family,
            "profile_id": self.profile_id,
            "profile_label_hash": _hash_ref(self.profile_id),
            "council_member_label_hash": _hash_ref(self.council_member) if self.council_member else None,
            "workspace_label_hash": _hash_ref(self.workspace_label) if self.workspace_label else None,
            "acquisition_authority": self.acquisition_authority,
            "authorization_ref_hash": _hash_ref(self.authorization_ref or self.acquisition_authority),
            "acquisition_method": self.acquisition_method,
            "export_timestamp": self.export_timestamp,
            "snapshot_hash": self.snapshot_hash,
            "expected_counts_by_record_class": _clean_counts(self.expected_counts_by_record_class),
            "observed_counts_by_record_class": _clean_counts(self.observed_counts_by_record_class),
            "imported_counts_by_cmc_table": _clean_counts(self.imported_counts_by_mnemoir_table),
            "skipped_counts_by_reason": _clean_counts(self.skipped_counts_by_reason),
            "degraded_counts_by_reason": _clean_counts(self.degraded_counts_by_reason),
            "malformed_count": int(self.malformed_count),
            "unsupported_count": int(self.unsupported_count),
            "duplicate_count": int(self.duplicate_count),
            "compacted_count": int(self.compacted_count),
            "proposal_staged_count": int(self.proposal_staged_count),
            "evidence_only_count": int(self.evidence_only_count),
            "canonical_promotion_count": int(self.canonical_promotion_count),
            "explicit_exclusions": list(self.explicit_exclusions),
            "deferred_sources": list(self.deferred_sources),
            "proposal_policy": self.proposal_policy,
            "content_included": bool(self.content_included),
            "path_redacted": bool(self.path_redacted),
        }
        verdict, reasons = reconcile_manifest_row(row)
        row["reconciliation_verdict"] = verdict
        row["verdict_reasons"] = reasons
        return row


def create_manifest_row(**kwargs: Any) -> dict[str, Any]:
    """Create and validate a leak-safe manifest row dictionary."""
    return MigrationManifestRow(**kwargs).to_dict()


def inventory_summary_to_manifest_rows(*, profile_id: str, inventory: dict[str, Any], acquisition_authority: str = "controlled_fixture_or_export_authority") -> list[dict[str, Any]]:
    """Convert a compat 15.1 inventory summary into compat 15.1A manifest rows.

    This consumes only redacted inventory counts/hashes and keeps content excluded.
    """
    rows: list[dict[str, Any]] = []
    for summary in inventory.get("source_summaries", []):
        family = str(summary.get("source_family") or "other_authorized_export")
        if family == "pre_honcho_local_memory_file":
            basename = summary.get("file_basename")
            family = "hermes_memory_md" if basename == "MEMORY.md" else "hermes_user_md" if basename == "USER.md" else "council_profile_memory"
        elif family == "honcho_export_or_snapshot":
            family = "honcho_export"
        elif family == "controlled_markdown_vault_directory":
            family = "obsidian_vault_export"
        elif family == "generated_scale_fixture":
            family = "generated_scale_fixture"
        rows.append(create_manifest_row(
            source_family=family,
            profile_id=profile_id,
            acquisition_authority=acquisition_authority,
            acquisition_method="generated_scale_fixture" if family == "generated_scale_fixture" else "controlled_local_copy",
            export_timestamp=inventory.get("finished_at") or inventory.get("started_at"),
            snapshot_hash=summary.get("source_hash"),
            expected_counts_by_record_class=dict(summary.get("record_class_counts") or {}),
            observed_counts_by_record_class=dict(summary.get("record_class_counts") or {}),
            imported_counts_by_mnemoir_table={},
            duplicate_count=int(inventory.get("duplicate_content_hashes") or 0),
            evidence_only_count=int(summary.get("record_count") or 0) if family in {"session_search_export", "obsidian_vault_export"} else 0,
            proposal_policy="evidence_only_review_proposal_deferred" if family in {"session_search_export", "obsidian_vault_export"} else "review_required_no_silent_promotion",
        ))
    for blocked in inventory.get("blocked_sources", []):
        rows.append(create_manifest_row(
            source_family="other_authorized_export",
            profile_id=profile_id,
            acquisition_authority=acquisition_authority,
            acquisition_method="controlled_local_copy",
            export_timestamp=inventory.get("finished_at") or inventory.get("started_at"),
            snapshot_hash=blocked.get("source_ref_hash"),
            expected_counts_by_record_class={},
            observed_counts_by_record_class={},
            imported_counts_by_mnemoir_table={},
            degraded_counts_by_reason={str(blocked.get("reason") or "blocked_source"): 1},
            deferred_sources=[str(blocked.get("reason") or "blocked_source")],
        ))
    return rows


def reconcile_manifest_row(row: dict[str, Any]) -> tuple[str, list[str]]:
    """Return row verdict and reasons for a manifest row."""
    reasons: list[str] = []
    for key in REQUIRED_ROW_KEYS:
        if key not in row:
            reasons.append(f"missing_required_field:{key}")
    family = str(row.get("source_family") or "")
    if family not in SUPPORTED_SOURCE_FAMILIES:
        reasons.append("unsupported_source_family")
    if row.get("content_included") is not False or row.get("path_redacted") is not True:
        reasons.append("leak_safe_output_contract_not_met")
    if int(row.get("canonical_promotion_count") or 0) != 0:
        reasons.append("canonical_promotion_requires_separate_review_lane")
    acquisition_method = str(row.get("acquisition_method") or "")
    deferred = list(row.get("deferred_sources") or [])
    exclusions = list(row.get("explicit_exclusions") or [])
    expected_total = _count_sum(row.get("expected_counts_by_record_class"))
    observed_total = _count_sum(row.get("observed_counts_by_record_class"))
    imported = _clean_counts(row.get("imported_counts_by_cmc_table"))
    if acquisition_method == "deferred_authorization_required" or deferred:
        reasons.append("source_family_deferred_or_authorization_required")
    if expected_total and not observed_total:
        reasons.append("expected_source_has_no_observed_export_count")
    if observed_total and not row.get("snapshot_hash"):
        reasons.append("observed_source_missing_snapshot_hash")
    if observed_total and acquisition_method != "generated_scale_fixture":
        for table in _IMPORT_REQUIRED_TABLES:
            if imported.get(table, 0) <= 0:
                reasons.append(f"observed_source_missing_import_table:{table}")
    if observed_total and acquisition_method == "generated_scale_fixture" and imported.get("raw_events", 0) and imported.get("raw_events", 0) < observed_total:
        reasons.append("bounded_subset_import_only_not_full_real_corpus")
    if any(_count_sum(row.get(key)) for key in ("skipped_counts_by_reason", "degraded_counts_by_reason")) or int(row.get("malformed_count") or 0) or int(row.get("unsupported_count") or 0):
        reasons.append("source_inputs_skipped_degraded_or_unsupported")
    if exclusions:
        reasons.append("explicit_exclusions_present")
    if str(row.get("proposal_policy") or "") == "evidence_only_review_proposal_deferred":
        reasons.append("evidence_only_proposal_staging_deferred")

    if any(reason in reasons for reason in ["canonical_promotion_requires_separate_review_lane", "leak_safe_output_contract_not_met"]):
        return "NO-GO", reasons
    if any(reason.startswith("missing_required_field") or reason in {"unsupported_source_family", "source_family_deferred_or_authorization_required", "expected_source_has_no_observed_export_count", "observed_source_missing_snapshot_hash"} or reason.startswith("observed_source_missing_import_table") for reason in reasons):
        return "BLOCKED", reasons
    if reasons:
        return "PARTIAL", reasons
    return "PASS", ["expected_observed_imported_counts_reconciled"]


def reconcile_migration_manifest(*, manifest_rows: Iterable[dict[str, Any]], expected_source_families: Iterable[str] = REQUIRED_SOURCE_FAMILIES, forbidden_action_flags: dict[str, bool] | None = None) -> dict[str, Any]:
    """Reconcile a complete migration manifest and fail closed on omissions."""
    rows = [dict(row) for row in manifest_rows]
    family_counts = Counter(str(row.get("source_family") or "") for row in rows)
    missing = [family for family in expected_source_families if not family_counts.get(family)]
    normalized_rows: list[dict[str, Any]] = []
    row_verdicts: list[str] = []
    for row in rows:
        verdict, reasons = reconcile_manifest_row(row)
        row["reconciliation_verdict"] = verdict
        row["verdict_reasons"] = reasons
        normalized_rows.append(row)
        row_verdicts.append(verdict)
    flags = {key: bool(value) for key, value in (forbidden_action_flags or {}).items()}
    forbidden_true = sorted(key for key in _FORBIDDEN_ACTION_FLAGS if flags.get(key))
    status_reasons: list[str] = []
    if missing:
        status_reasons.append("expected_source_families_missing")
    if forbidden_true:
        status_reasons.append("forbidden_action_flag_true")
    verdict = _worst(row_verdicts)
    if forbidden_true:
        verdict = "NO-GO"
    elif missing and VERDICT_RANK[verdict] < VERDICT_RANK["BLOCKED"]:
        verdict = "BLOCKED"
    totals = {
        "expected_records": sum(_count_sum(row.get("expected_counts_by_record_class")) for row in normalized_rows),
        "observed_records": sum(_count_sum(row.get("observed_counts_by_record_class")) for row in normalized_rows),
        "imported_raw_events": sum(int(row.get("imported_counts_by_cmc_table", {}).get("raw_events", 0)) for row in normalized_rows),
        "imported_evidence_items": sum(int(row.get("imported_counts_by_cmc_table", {}).get("evidence_items", 0)) for row in normalized_rows),
        "imported_provenance_edges": sum(int(row.get("imported_counts_by_cmc_table", {}).get("provenance_edges", 0)) for row in normalized_rows),
        "proposal_staged": sum(int(row.get("proposal_staged_count") or 0) for row in normalized_rows),
        "evidence_only": sum(int(row.get("evidence_only_count") or 0) for row in normalized_rows),
        "canonical_promotion_count": sum(int(row.get("canonical_promotion_count") or 0) for row in normalized_rows),
        "duplicate_count": sum(int(row.get("duplicate_count") or 0) for row in normalized_rows),
    }
    scale_rows = [row for row in normalized_rows if row.get("source_family") == "generated_scale_fixture"]
    real_rows = [row for row in normalized_rows if row.get("source_family") != "generated_scale_fixture"]
    generated_observed = sum(_count_sum(row.get("observed_counts_by_record_class")) for row in scale_rows)
    generated_imported = sum(int(row.get("imported_counts_by_cmc_table", {}).get("raw_events", 0)) for row in scale_rows)
    real_observed = sum(_count_sum(row.get("observed_counts_by_record_class")) for row in real_rows)
    real_imported = sum(int(row.get("imported_counts_by_cmc_table", {}).get("raw_events", 0)) for row in real_rows)
    scale_status = {
        "generated_200k_inventory_supported": generated_observed >= 200_000,
        "bounded_subset_import_verified": bool(generated_imported and generated_imported < generated_observed),
        "full_real_corpus_import_verified": bool(real_observed and real_imported >= real_observed and verdict == "PASS"),
    }
    compat_15_2_entry_verdict = "PROCEED_TO_CONTROLLED_TEST_PROFILE_WITH_WATCH_ITEMS" if verdict in {"PASS", "PARTIAL"} else "BLOCKED_UNTIL_MANIFEST_RECONCILIATION"
    return {
        "schema": "mnemoir_provenance.migration_manifest.v1",
        "generated_at": now_utc(),
        "content_included": False,
        "path_redacted": True,
        "required_source_families": list(expected_source_families),
        "missing_source_families": missing,
        "source_family_counts": dict(family_counts),
        "rows": normalized_rows,
        "totals": totals,
        "large_corpus_status": scale_status,
        "forbidden_action_flags": {key: bool(flags.get(key, False)) for key in sorted(_FORBIDDEN_ACTION_FLAGS)},
        "forbidden_action_hits": forbidden_true,
        "reconciliation_verdict": verdict,
        "status_reasons": status_reasons,
        "compat_15_2_entry_verdict": compat_15_2_entry_verdict,
        "no_flip_no_live_mutation": True,
    }


def validate_council_review_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Validate compat 15.1A council-review proof without treating Telegram sends as processing."""
    accepted = bool(evidence.get("b2b_envelope_processed_by_receiver_gateway") or evidence.get("profile_scoped_fallback_session_id"))
    return {
        "status": "ok" if accepted else "blocked",
        "council_review_processed": accepted,
        "telegram_send_receipt_only": bool(evidence.get("telegram_send_receipt")) and not accepted,
        "valid_evidence_types": ["b2b_envelope_processed_by_receiver_gateway", "profile_scoped_fallback_session_id"],
        "content_included": False,
        "path_redacted": True,
    }


def manifest_no_leak_forbidden_scan(payloads: Iterable[Any]) -> dict[str, Any]:
    """Focused no-leak/forbidden-action scan for manifest/reconciliation outputs."""
    text = "\n".join(json_dumps(payload) if not isinstance(payload, str) else payload for payload in payloads)
    lowered = text.lower()
    forbidden_markers = (
        "api_key",
        "apikey",
        "password=",
        "token=",
        "secret=",
        "sk-",
        ".hermes/profiles",
        "raw memory body",
        "raw user body",
        "compat151_private",
    )
    forbidden_phrases = (
        "honcho deletion performed true",
        "compat 15.2 controlled activation performed true",
        "feature-complete replacement claim true",
        "silent canonical promotion true",
    )
    hits = sorted({marker for marker in forbidden_markers + forbidden_phrases if marker in lowered})
    return {
        "status": "ok" if not hits else "blocked",
        "forbidden_hits": hits,
        "checked_payloads": True,
        "content_included": False,
        "path_redacted": True,
    }
