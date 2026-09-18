"""Synthetic profile fixtures only; never read a deployed runtime home."""
import argparse
import pytest
from mnemoir_provenance import cli
from mnemoir_provenance.db import connect, initialize_database
from mnemoir_provenance.hermes_provider import register_profile_sources, context_packet_for_profile
from mnemoir_provenance.live_overflow import DEFAULT_PROFILE_IDS
from mnemoir_provenance.scope import (
    ScopeError, ensure_profile_actor_scope, bind_profile_metadata,
    authorized_sources_for_profile,
)


def test_profile_provisioning_and_stable_actor_scope(tmp_path):
    root = tmp_path / "profile"
    root.mkdir()
    for filename in ("MEMORY.md", "USER.md"):
        (root / filename).write_text("synthetic profile fact\n")
    with connect(tmp_path / "scope.sqlite") as conn:
        initialize_database(conn)
        result = register_profile_sources(conn, "fixture_owner", root)
        actor = ensure_profile_actor_scope(conn, profile_id="fixture_owner")
        assert result["status"] == "ok"
        row = conn.execute("SELECT actor_id FROM actors WHERE profile_name=? AND is_active=1", ("fixture_owner",)).fetchone()
        assert row[0] == actor["actor_id"]
        grants = {r[0] for r in conn.execute("SELECT scope_id FROM access_grants WHERE actor_id=? AND scope_type='source' AND permission='read' AND expires_at IS NULL", (actor["actor_id"],))}
        assert {s["source_id"] for s in result["sources"]} <= grants
        bound = bind_profile_metadata(conn, profile_id="fixture_owner", actor_id="obsolete-fixture-actor")
        assert bound["actor_id"] == actor["actor_id"]
        assert conn.execute("SELECT 1 FROM actors WHERE actor_id='obsolete-fixture-actor'").fetchone() is None
        other = ensure_profile_actor_scope(conn, profile_id="fixture_other")
        for operation in (
            lambda: ensure_profile_actor_scope(conn, profile_id="fixture_owner", actor_id=other["actor_id"]),
            lambda: bind_profile_metadata(conn, profile_id="fixture_owner", actor_id=other["actor_id"]),
            lambda: authorized_sources_for_profile(conn, profile_id="fixture_owner", actor_id=other["actor_id"]),
        ):
            with pytest.raises(ScopeError, match="actor_profile_mismatch"):
                operation()
        assert conn.execute("SELECT profile_name FROM actors WHERE actor_id=?", (other["actor_id"],)).fetchone()[0] == "fixture_other"


def test_legacy_source_actor_repair_before_cited_recall(tmp_path):
    from mnemoir_provenance.db import now_utc, sha256_text, stable_id
    marker = "synthetic-legacy-citation-needle"
    source = "live_overflow_trim:fixture_owner:USER.md"
    pointer = "hermes-profile://fixture_owner/USER.md#removed-block-1"
    timestamp = now_utc()
    digest = sha256_text(marker)
    event = stable_id("fixture", source, digest)
    evidence = stable_id("evidence", event, digest)
    with connect(tmp_path / "legacy.sqlite") as conn:
        initialize_database(conn)
        conn.execute("INSERT INTO sources(source_id,source_type,display_name,external_ref,profile_id,overflow_kind,read_authority,write_authority,authority_level,health,created_at,updated_at) VALUES (?, 'hermes_markdown_overflow','Synthetic legacy source',?,'fixture_owner','user_md','read_only','write_allowed','primary','healthy',?,?)", (source, pointer, timestamp, timestamp))
        conn.execute("INSERT INTO raw_events(event_id,source_id,event_type,content,content_hash,occurred_at,ingested_at,visibility,privacy_class,source_pointer,provenance_json,write_status) VALUES (?,?,'memory_block',?,?,?,?,'private','private',?,'{}','committed')", (event, source, marker, digest, timestamp, timestamp, pointer))
        conn.execute("INSERT INTO evidence_items(evidence_id,kind,source_id,raw_event_id,uri,locator_json,quote_text,content_hash,trust_score,privacy_class,observed_at,created_at) VALUES (?,'receipt',?,?,?,'{}',?,?,1.0,'private',?,?)", (evidence, source, event, pointer, marker, digest, timestamp, timestamp))
        conn.commit()
        assert conn.execute("SELECT 1 FROM actors WHERE profile_name='fixture_owner'").fetchone() is None
        packet = context_packet_for_profile(conn, marker, profile_id="fixture_owner", limit=5)
        assert packet["status"] == "ok"
        assert packet["cited_context"]
        assert {item["source_id"] for item in packet["cited_context"]} == {source}
        actor = packet["profile_scope"]["actor_id"]
        assert conn.execute("SELECT 1 FROM access_grants WHERE actor_id=? AND scope_type='source' AND scope_id=? AND permission='read' AND expires_at IS NULL", (actor, source)).fetchone()
        conn.execute("SAVEPOINT fixture_transaction")
        ensure_profile_actor_scope(conn, profile_id="fixture_transient", ensure_runtime=False, commit=False)
        conn.execute("ROLLBACK TO fixture_transaction")
        assert conn.execute("SELECT 1 FROM actors WHERE profile_name='fixture_transient'").fetchone() is None


def test_cli_uses_complete_coordinator_default_denominator(monkeypatch):
    observed = {}
    def status(*, profile_ids, hermes_home):
        observed.update(profile_ids=profile_ids, hermes_home=hermes_home)
        return {"status": "ok"}
    monkeypatch.setattr(cli, "live_overflow_status", status)
    assert cli.cmd_hermes_live_overflow_status(argparse.Namespace(profile_id=None, hermes_home="/controlled-fixture-home")) == 0
    assert observed == {"profile_ids": DEFAULT_PROFILE_IDS, "hermes_home": "/controlled-fixture-home"}
    assert DEFAULT_PROFILE_IDS[0] == "default"
    assert len(DEFAULT_PROFILE_IDS) == 8
    assert len(set(DEFAULT_PROFILE_IDS)) == len(DEFAULT_PROFILE_IDS)
