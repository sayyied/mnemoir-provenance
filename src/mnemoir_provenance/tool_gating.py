"""Leak-safe Mnemoir memory-provider tool gating evaluation.

This module mirrors the Hermes memory-provider tool surface gate without
importing Hermes, mutating live config, or initializing a provider.  It is used
for GAP-011 negative proof/status objects and tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

MNEMOIR_PROVIDER_ID = "mnemoir_provenance"
MEMORY_TOOLSET = "memory"

BUILTIN_MEMORY_TOOL_NAMES = frozenset({"memory"})
HONCHO_TOOL_NAMES = frozenset(
    {
        "honcho_profile",
        "honcho_search",
        "honcho_reasoning",
        "honcho_context",
        "honcho_conclude",
    }
)


@dataclass(frozen=True)
class ToolGatingRequest:
    """Controlled inputs for deterministic Mnemoir memory-tool gating status."""

    schemas: Sequence[Mapping[str, Any]]
    selected_provider_id: str = MNEMOIR_PROVIDER_ID
    memory_enabled: bool = True
    skip_memory: bool = False
    enabled_toolsets: Sequence[str] | None = None
    allow_tools: Sequence[str] | None = None
    deny_tools: Sequence[str] | None = None
    existing_tool_names: Sequence[str] | None = None
    builtin_memory_tool_names: Sequence[str] = tuple(BUILTIN_MEMORY_TOOL_NAMES)
    honcho_tool_names: Sequence[str] = tuple(HONCHO_TOOL_NAMES)


def _names(values: Iterable[Any] | None) -> list[str]:
    if values is None:
        return []
    return sorted({str(value) for value in values if str(value).strip()})


def _schema_names(schemas: Sequence[Mapping[str, Any]]) -> list[str]:
    return _names(schema.get("name") for schema in schemas if isinstance(schema, Mapping))


def evaluate_mnemoir_tool_gating(request: ToolGatingRequest) -> dict[str, Any]:
    """Return leak-safe Mnemoir memory-tool exposure status.

    The result intentionally contains only provider IDs, tool names/counts,
    gate/filter reasons, and side-effect posture.  It does not include paths,
    config values, profile markdown, transcript/vault content, credentials, or
    raw provider internals.
    """

    requested_tool_names = _schema_names(request.schemas)
    requested_tool_set = set(requested_tool_names)
    allow_set = set(_names(request.allow_tools)) if request.allow_tools is not None else None
    deny_set = set(_names(request.deny_tools))
    enabled_toolsets = _names(request.enabled_toolsets) if request.enabled_toolsets is not None else None
    existing_tool_names = set(_names(request.existing_tool_names))
    builtin_names = set(_names(request.builtin_memory_tool_names))
    honcho_names = set(_names(request.honcho_tool_names))
    reserved_names = builtin_names | honcho_names

    disabled_reasons: list[str] = []
    if request.skip_memory:
        disabled_reasons.append("memory_disabled_skip_memory")
    if not request.memory_enabled:
        disabled_reasons.append("memory_disabled_config")
    if enabled_toolsets is not None and MEMORY_TOOLSET not in enabled_toolsets:
        disabled_reasons.append("memory_toolset_not_enabled")

    intrinsic_collisions = sorted(requested_tool_set & reserved_names)
    existing_collisions = sorted(requested_tool_set & existing_tool_names)
    collision_names = sorted(set(intrinsic_collisions) | set(existing_collisions))
    collision_sources = []
    if intrinsic_collisions:
        collision_sources.append("reserved_builtin_or_honcho_name")
    if existing_collisions:
        collision_sources.append("existing_tool_name")

    if disabled_reasons:
        exposed_tool_names: list[str] = []
        excluded_tool_names = requested_tool_names
        gating_state = "disabled"
        gating_reasons = disabled_reasons
        fail_closed = True
    elif collision_names:
        exposed_tool_names = []
        excluded_tool_names = requested_tool_names
        gating_state = "collision_fail_closed"
        gating_reasons = ["tool_name_collision_detected"]
        fail_closed = True
    else:
        exposed_tool_names = requested_tool_names
        filter_reasons: list[str] = []
        if allow_set is not None:
            exposed_tool_names = [name for name in exposed_tool_names if name in allow_set]
            filter_reasons.append("explicit_allow_list_applied")
        if deny_set:
            before = set(exposed_tool_names)
            exposed_tool_names = [name for name in exposed_tool_names if name not in deny_set]
            if before != set(exposed_tool_names):
                filter_reasons.append("explicit_deny_list_applied")
        excluded_tool_names = [name for name in requested_tool_names if name not in set(exposed_tool_names)]
        gating_state = "enabled" if exposed_tool_names else "filtered_empty"
        gating_reasons = filter_reasons or ["memory_tool_path_enabled"]
        fail_closed = False

    return {
        "provider_id": MNEMOIR_PROVIDER_ID,
        "selected_provider_id": request.selected_provider_id,
        "surface": "memoryprovider_tool_gating",
        "gating_state": gating_state,
        "gating_reasons": gating_reasons,
        "disabled_reasons": disabled_reasons,
        "requested_tool_count": len(requested_tool_names),
        "requested_tool_names": requested_tool_names,
        "exposed_tool_count": len(exposed_tool_names),
        "exposed_tool_names": exposed_tool_names,
        "excluded_tool_count": len(excluded_tool_names),
        "excluded_tool_names": excluded_tool_names,
        "allow_list_applied": allow_set is not None,
        "deny_list_applied": bool(deny_set),
        "enabled_toolsets": enabled_toolsets if enabled_toolsets is not None else "unfiltered",
        "memory_toolset_requested": enabled_toolsets is None or MEMORY_TOOLSET in enabled_toolsets,
        "collision_detected": bool(collision_names),
        "collision_names": collision_names,
        "collision_sources": sorted(collision_sources),
        "builtin_memory_tool_names_checked": sorted(builtin_names),
        "honcho_tool_names_checked": sorted(honcho_names),
        "fail_closed": fail_closed,
        "provider_initialization_required_for_status": False,
        "provider_side_effects_required_for_status": False,
        "live_config_mutation_performed": False,
        "provider_activation_performed": False,
        "gateway_restart_performed": False,
        "cron_systemd_autostart_mutation_performed": False,
        "honcho_api_called": False,
        "session_search_db_read": False,
        "real_profile_markdown_read": False,
        "real_profile_markdown_writeback": False,
        "raw_content_included": False,
        "paths_included": False,
        "credentials_included": False,
    }
