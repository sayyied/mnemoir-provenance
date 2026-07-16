"""compat 11 local operator API/runtime surface.

This is a local Python API for tool consumers over canonical DB records. It is not
a public dashboard, hosted API, gateway, remote service, or production UI.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .operator_surface import (
    OperatorSurfaceError,
    _assert_safe,
    _clean_value,
    approval_needed,
    autonomy_status,
    council_status,
    hermes_status,
    operator_overview,
    projection_surface_status,
    proposals_status,
    recall_status,
    source_health,
)
from .scope import scope_status

OPERATOR_API_SCHEMA_VERSION = "compat11_local_operator_api_v1"
API_VIEWS = {
    "overview",
    "sources",
    "recall",
    "proposals",
    "council",
    "autonomy",
    "hermes",
    "projection",
    "approval-needed",
    "scope",
}


class OperatorAPIError(ValueError):
    """Fail-closed local operator API error."""


def _wrap(view: str, data: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "status": data.get("status", "ok"),
        "schema": OPERATOR_API_SCHEMA_VERSION,
        "view": view,
        "surface": "local_python_api",
        "record_backed": True,
        "canonical_storage": "mnemoir_provenance_sqlite_db",
        "machine_readable": True,
        "leak_safe": True,
        "mock_dashboard_state_used": False,
        "public_dashboard": False,
        "remote_access": False,
        "gateway_exposure": False,
        "live_network_io_performed": False,
        "real_hermes_profile_markdown_read": False,
        "hermes_markdown_writeback_performed": False,
        "data": data,
    }
    payload = _clean_value(payload)
    _assert_safe(payload)
    return payload


def operator_api_view(
    conn: sqlite3.Connection,
    view: str,
    *,
    query: str = "Council memory",
    projection_root: str | None = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Return one stable machine-readable operator API view from real DB records."""
    if view not in API_VIEWS:
        raise OperatorAPIError("unknown_operator_api_view")
    try:
        if view == "overview":
            return _wrap(view, operator_overview(conn, query=query, projection_root=projection_root, limit=limit))
        if view == "sources":
            return _wrap(view, source_health(conn))
        if view == "recall":
            return _wrap(view, recall_status(conn, query, limit=limit))
        if view == "proposals":
            return _wrap(view, proposals_status(conn, limit=limit))
        if view == "council":
            return _wrap(view, council_status(conn, limit=limit))
        if view == "autonomy":
            return _wrap(view, autonomy_status(conn, limit=limit))
        if view == "hermes":
            return _wrap(view, hermes_status(conn))
        if view == "projection":
            return _wrap(view, projection_surface_status(projection_root))
        if view == "approval-needed":
            return _wrap(view, approval_needed(conn, limit=limit))
        if view == "scope":
            return _wrap(view, scope_status(conn, limit=limit))
    except OperatorSurfaceError as error:
        raise OperatorAPIError(str(error)) from error
    raise OperatorAPIError("unreachable_operator_api_view")


def operator_api_index(conn: sqlite3.Connection, *, query: str = "Council memory", projection_root: str | None = None, limit: int = 10) -> dict[str, Any]:
    """Return all compat 11 operator API views with stable schemas."""
    views = {
        name: operator_api_view(conn, name, query=query, projection_root=projection_root, limit=limit)
        for name in ["sources", "recall", "proposals", "council", "autonomy", "hermes", "projection", "approval-needed", "scope"]
    }
    payload = {
        "status": "ok",
        "schema": OPERATOR_API_SCHEMA_VERSION,
        "view": "index",
        "surface": "local_python_api",
        "available_views": sorted(API_VIEWS),
        "record_backed": True,
        "mock_dashboard_state_used": False,
        "public_dashboard": False,
        "remote_access": False,
        "gateway_exposure": False,
        "views": views,
    }
    payload = _clean_value(payload)
    _assert_safe(payload)
    return payload
