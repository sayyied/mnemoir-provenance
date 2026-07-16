from mnemoir_provenance.autonomy import kill_tick, pause_tick, plan_tick, resume_tick, run_tick
from mnemoir_provenance.council import create_assignment, create_objective, lifecycle
from mnemoir_provenance.curation import create_proposal, review_proposal, write_memory
from mnemoir_provenance.db import connect, initialize_database
from mnemoir_provenance.retrieval import rebuild_retrieval_index, retrieve
from mnemoir_provenance.scoring import apply_scoring_scenario


def test_hybrid_retrieval_and_heat_is_not_truth(seeded_db):
    with connect(seeded_db) as conn:
        initialize_database(conn)
        proposal = create_proposal(conn, title="Hybrid memory", summary="Local deterministic embedding", body="Citations and provenance remain truth authority.", evidence_ids=["demo_evidence"])
        review_proposal(conn, proposal_id=proposal["proposal_id"], action="approve", reviewer_actor_id="actor_operator_compat02")
        memory_id = write_memory(conn, proposal_id=proposal["proposal_id"])["memory_id"]
        apply_scoring_scenario(conn, memory_id=memory_id, scenario="retrieval_success", occurred_at="2026-01-01T00:00:00Z")
        rebuild_retrieval_index(conn)
        result = retrieve(conn, "truth authority citations", mode="hybrid", limit=5)
        assert any(row["target_id"] == memory_id for row in result["cited_results"])
        assert result["semantic_similarity_truth_authority"] is False


def test_generic_multi_actor_records_and_bounded_autonomy(seeded_db):
    with connect(seeded_db) as conn:
        initialize_database(conn)
        objective = create_objective(conn, title="Synthetic objective", body="Exercise optional coordination records.", owner_actor_id="actor_orchestrator")
        assignment = create_assignment(conn, objective_id=objective["objective_id"], title="Synthetic assignment", body="Bounded local work.", assigned_actor_id="actor_engineer")
        planned = plan_tick(conn, objective_id=objective["objective_id"], assignment_id=assignment["assignment_id"], idempotency_key="synthetic-once")
        tick_id = planned["tick"]["tick_id"]
        pause_tick(conn, tick_id)
        assert run_tick(conn, tick_id=tick_id)["status"] == "paused"
        resume_tick(conn, tick_id)
        assert run_tick(conn, tick_id=tick_id)["status"] == "ok"
        assert run_tick(conn, tick_id=tick_id)["status"] == "deduped"
        other = plan_tick(conn, objective_id=objective["objective_id"], idempotency_key="synthetic-kill")
        kill_tick(conn, other["tick"]["tick_id"])
        assert run_tick(conn, tick_id=other["tick"]["tick_id"])["status"] == "cancelled"
        assert lifecycle(conn, objective["objective_id"])["objective"]["objective_id"] == objective["objective_id"]
