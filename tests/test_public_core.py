from mnemoir_provenance.curation import create_proposal, read_memory, review_proposal, rollback_memory, tombstone_memory, write_memory
from mnemoir_provenance.db import connect, initialize_database
from mnemoir_provenance.recall import recall


def test_cited_recall_abstention_and_degraded_coverage(seeded_db):
    with connect(seeded_db) as conn:
        initialize_database(conn)
        healthy = recall(conn, "source grounded memory", limit=5)
        assert healthy["cited_results"]
        assert healthy["cited_results"][0]["source_id"] == "demo_source"
        empty = recall(conn, "unfindable-zebra-quantum", limit=5)
        assert empty["result_count"] == 0
        conn.execute("INSERT INTO sources(source_id,source_type,display_name,external_ref,read_authority,write_authority,authority_level,health,failure_reason,created_at,updated_at) VALUES('offline_source','manual','Offline synthetic source','fixture://offline','read_only','none','secondary','degraded','synthetic outage',datetime('now'),datetime('now'))")
        conn.commit()
        degraded = recall(conn, "source grounded memory", limit=5)
        assert degraded["status"] == "degraded"
        assert degraded["source_coverage"]["missing_or_degraded_sources"]


def test_proposal_review_write_version_tombstone_and_rollback(seeded_db):
    with connect(seeded_db) as conn:
        initialize_database(conn)
        proposal = create_proposal(conn, title="Demo memory", summary="Source-grounded demo", body="The demo uses review before write.", evidence_ids=["demo_evidence"], source_event_ids=["demo_event"])
        assert proposal["proposal_status"] == "proposed"
        review_proposal(conn, proposal_id=proposal["proposal_id"], action="approve", reviewer_actor_id="actor_operator_compat02", reason="synthetic review")
        written = write_memory(conn, proposal_id=proposal["proposal_id"])
        memory_id = written["memory_id"]
        assert read_memory(conn, memory_id)["memory"]["current_version"] == 1
        assert tombstone_memory(conn, memory_id=memory_id, reason="synthetic lifecycle")["memory_status"] == "tombstoned"
        restored = rollback_memory(conn, memory_id=memory_id, version=1, reason="synthetic rollback")
        assert restored["memory_status"] == "active"
        assert restored["read_back"]["current_version"]["body"] == "The demo uses review before write."
