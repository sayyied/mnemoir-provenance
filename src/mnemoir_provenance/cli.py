"""Command-line interface for Mnemoir Provenance compat 01."""
from __future__ import annotations
import argparse
import json
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any
from .audit import list_audit_events
from .benchmark import BenchmarkError, benchmark_status, run_benchmark
from .autonomy import AutonomyError, kill_tick, list_ticks, pause_tick, plan_and_run_tick, plan_tick, receipt as autonomy_receipt, resume_tick, run_tick, status as autonomy_status
from .council import CouncilError, attach_evidence, bind_role, create_assignment, create_handoff, create_objective, create_record, csv_from_cli, lifecycle, list_assignments, list_evidence, list_handoffs, list_members, list_objectives, list_reviews, record_review, refs_from_cli_args, search_handoffs, search_objectives, show_handoff, show_objective, update_assignment_status, update_objective_status
from .curation import CurationError, create_proposal, inspect_proposal, list_proposals, proposal_from_cli_args, read_memory, review_proposal, rollback_memory, tombstone_memory, write_memory
from .db import connect, initialize_database
from .health import HealthError, open_local_health_report
from .live_overflow import LIVE_OVERFLOW_AUTHORIZATION, LiveOverflowError, WritebackAuthorization, execute_writeback, reconcile_writeback, rollback_writeback, request_from_authorization, execute_live_overflow_trim, ingest_pending_evidence_spools, live_overflow_status, run_live_overflow_coordinator
from .experiments import ExperimentError, candidate_experiment, candidate_experiment_cases, default_fixture_suite, define_memory_model_version, list_candidate_experiments, list_memory_model_versions, run_candidate_experiment
from .improvement_proposals import ImprovementProposalError, active_local_memory_model_version, evaluate_promotion_recommendation, generate_improvement_proposals, improvement_proposal, improvement_status, list_improvement_proposals, promote_memory_model_version, rollback_memory_model_promotion, review_improvement_proposal, run_or_attach_proposal_experiment
from .learning import LearningError, allowed_learning_event_types, allowed_learning_failure_classes, allowed_learning_outcome_labels, learning_event, learning_failure_clusters, list_learning_events, record_learning_event
from .migration_readiness import MigrationReadinessError, dry_run_migration, generate_message_scale_fixture, import_generated_message_scale_fixture, inventory_migration_inputs, migration_readiness_report
from .hermes_provider import HermesProviderError, context_packet, ingest_profile_markdown, markdown_writeback_status, overflow_pressure_status, provider_status, register_profile_sources, tool_manifest
from .ingest import ingest_repo_docs
from .operator_surface import OperatorSurfaceError, approval_needed as operator_approval_needed, autonomy_status as operator_autonomy_status, council_status as operator_council_status, hermes_status as operator_hermes_status, operator_overview, projection_surface_status, proposals_status as operator_proposals_status, recall_status as operator_recall_status, source_health as operator_source_health
from .operator_api import OperatorAPIError, operator_api_index, operator_api_view
from .scope import ScopeError
from .policy_guard import PolicyGuardError, approval_needed_queue as policy_approval_needed_queue, approve_writeback, classify_action, diff_fixture_file, dry_run_writeback, propose_writeback, read_back_fixture, rollback_fixture, snapshot_fixture_root, tombstone_writeback, writeback_fixture
from .recall import recall
from .retrieval import RetrievalError, explain, rebuild_retrieval_index, record_feedback, retrieval_status, retrieve
from .wiki_projection import ProjectionError, write_projection
from .scoring import ScoringError, apply_scoring_scenario, decay_memory, ranked_memories, review_queue, score_history, score_summary
from .service import ServiceError, service_restart, service_start, service_status, service_stop
from .plugin_install import PluginInstallError, install_hermes_plugin
from .worker import WorkerError, clear_stop, enqueue_promotion, request_stop, run_bounded_worker, worker_status
from .sources import register_sources

def repo_root() -> Path:
    configured = os.environ.get('MNEMOIR_ROOT')
    return Path(configured).expanduser().resolve() if configured else Path(__file__).resolve().parents[2]

def _json_print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))

def _open_initialized(db_path: str | None=None):
    conn = connect(db_path)
    initialize_database(conn)
    return conn

def cmd_sources(args: argparse.Namespace) -> int:
    root = repo_root()
    with _open_initialized(args.db) as conn:
        sources = register_sources(conn, root)
    _json_print({'status': 'ok', 'sources': sources})
    return 0

def cmd_ingest(args: argparse.Namespace) -> int:
    root = repo_root()
    with _open_initialized(args.db) as conn:
        result = ingest_repo_docs(conn, root, limit=args.limit)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded'} else 1

def cmd_recall(args: argparse.Namespace) -> int:
    root = repo_root()
    with _open_initialized(args.db) as conn:
        register_sources(conn, root)
        if args.mode == 'lexical':
            result = recall(conn, args.query, limit=args.limit)
            result['requested_mode'] = 'lexical'
            result['effective_mode'] = 'lexical'
        else:
            try:
                result = retrieve(conn, args.query, mode=args.mode, limit=args.limit)
            except RetrievalError as error:
                return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded', 'abstain'} else 1

def cmd_audit(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        events = list_audit_events(conn, limit=args.limit)
    _json_print({'status': 'ok', 'audit_events': events})
    return 0

def _fail_closed(error: CurationError | ScoringError | RetrievalError | CouncilError | AutonomyError | HermesProviderError | ProjectionError | OperatorSurfaceError | OperatorAPIError | ScopeError | HealthError | ServiceError | PolicyGuardError | BenchmarkError | LearningError | ExperimentError | ImprovementProposalError | MigrationReadinessError | LiveOverflowError) -> int:
    _json_print({'status': 'error', 'error': str(error)})
    return 1

def cmd_migration_inventory(args: argparse.Namespace) -> int:
    try:
        result = inventory_migration_inputs(profile_id=args.profile_id, roots=_csv_arg(args.roots), allowed_roots=_csv_arg(args.allowed_roots), sample_limit=args.sample_limit)
    except MigrationReadinessError as error:
        return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded'} else 1

def cmd_migration_dry_run(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = dry_run_migration(conn, profile_id=args.profile_id, honcho_fixture_path=args.honcho_fixture_path, pre_honcho_memory_root=args.pre_honcho_memory_root, session_fixture_path=args.session_fixture_path, obsidian_vault_root=args.obsidian_vault_root, allowed_roots=_csv_arg(args.allowed_roots), query=args.query)
        except MigrationReadinessError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded'} else 1

def cmd_migration_readiness(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = migration_readiness_report(conn, profile_id=args.profile_id, query=args.query, context_budget_chars=args.context_budget_chars)
        except MigrationReadinessError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['compat_15_2_readiness_verdict'] in {'PASS', 'PARTIAL'} else 1

def cmd_migration_generate_scale(args: argparse.Namespace) -> int:
    try:
        result = generate_message_scale_fixture(args.output, records=args.records, profile_id=args.profile_id)
    except MigrationReadinessError as error:
        return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_migration_import_scale(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = import_generated_message_scale_fixture(conn, profile_id=args.profile_id, fixture_path=args.fixture_path, allowed_roots=_csv_arg(args.allowed_roots), chunk_size=args.chunk_size, max_records=args.max_records)
        except MigrationReadinessError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] == 'ok' else 1

def _json_arg(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    return json.loads(value)

def _csv_arg(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(',') if item.strip()]

def cmd_learning_record(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = record_learning_event(conn, event_type=args.event_type, outcome_label=args.outcome_label, failure_class=args.failure_class, severity=args.severity, profile_id=args.profile_id, actor_id=args.actor_id, session_id=args.session_id, query_id=args.query_id, memory_id=args.memory_id, proposal_id=args.proposal_id, source_id=args.source_id, raw_event_id=args.raw_event_id, evidence_ids=_csv_arg(args.evidence_ids), related_ids=_json_arg(args.related_ids_json, {}), input_text=args.input_text, output_text=args.output_text, metadata=_json_arg(args.metadata_json, {}), occurred_at=args.occurred_at)
        except (LearningError, json.JSONDecodeError) as error:
            return _fail_closed(LearningError(str(error)))
    _json_print(result)
    return 0

def cmd_learning_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        events = list_learning_events(conn, event_type=args.event_type, outcome_label=args.outcome_label, failure_class=args.failure_class, limit=args.limit)
    _json_print({'status': 'ok', 'learning_events': events})
    return 0

def cmd_learning_clusters(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        clusters = learning_failure_clusters(conn, limit=args.limit)
    _json_print({'status': 'ok', 'learning_failure_clusters': clusters})
    return 0

def cmd_learning_inspect(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            event = learning_event(conn, args.learning_event_id)
        except LearningError as error:
            return _fail_closed(error)
    _json_print({'status': 'ok', 'learning_event': event})
    return 0

def _fixture_suite_arg(args: argparse.Namespace) -> dict[str, Any]:
    if getattr(args, 'fixture_suite_json', None):
        return _json_arg(args.fixture_suite_json, {})
    if getattr(args, 'fixture_suite_path', None):
        return json.loads(Path(args.fixture_suite_path).read_text(encoding='utf-8'))
    return default_fixture_suite()

def cmd_experiment_model_define(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = define_memory_model_version(conn, kind=args.kind, config=_json_arg(args.config_json, {}), parent_model_version_id=args.parent_model_version_id, metadata=_json_arg(args.metadata_json, {}), created_at=args.created_at)
        except (ExperimentError, json.JSONDecodeError) as error:
            return _fail_closed(ExperimentError(str(error)))
    _json_print(result)
    return 0

def cmd_experiment_model_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            versions = list_memory_model_versions(conn, kind=args.kind, status=args.status, limit=args.limit)
        except ExperimentError as error:
            return _fail_closed(error)
    _json_print({'status': 'ok', 'memory_model_versions': versions})
    return 0

def cmd_experiment_run(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = run_candidate_experiment(conn, baseline_model_version_id=args.baseline_model_version_id, candidate_model_version_id=args.candidate_model_version_id, fixture_suite=_fixture_suite_arg(args), metadata=_json_arg(args.metadata_json, {}), started_at=args.started_at)
        except (ExperimentError, json.JSONDecodeError, OSError) as error:
            return _fail_closed(ExperimentError(str(error)))
    _json_print(result)
    return 0 if result.get('status') in {'pass', 'fail'} else 1

def cmd_experiment_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            experiments = list_candidate_experiments(conn, candidate_model_version_id=args.candidate_model_version_id, status=args.status, limit=args.limit)
        except ExperimentError as error:
            return _fail_closed(error)
    _json_print({'status': 'ok', 'candidate_experiments': experiments})
    return 0

def cmd_experiment_inspect(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            experiment = candidate_experiment(conn, args.experiment_id)
            cases = candidate_experiment_cases(conn, args.experiment_id, limit=args.case_limit)
        except ExperimentError as error:
            return _fail_closed(error)
    _json_print({'status': 'ok', 'experiment': experiment, 'cases': cases})
    return 0

def cmd_improve_propose(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            proposals = generate_improvement_proposals(conn, min_cluster_events=args.min_cluster_events, profile_id=args.profile_id, created_at=args.created_at)
        except ImprovementProposalError as error:
            return _fail_closed(error)
    _json_print({'status': 'ok', 'improvement_proposals': proposals})
    return 0

def cmd_improve_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            proposals = list_improvement_proposals(conn, status=args.status, limit=args.limit)
        except ImprovementProposalError as error:
            return _fail_closed(error)
    _json_print({'status': 'ok', 'improvement_proposals': proposals})
    return 0

def cmd_improve_inspect(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            proposal = improvement_proposal(conn, args.proposal_id)
        except ImprovementProposalError as error:
            return _fail_closed(error)
    _json_print({'status': 'ok', 'improvement_proposal': proposal})
    return 0

def cmd_improve_experiment(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = run_or_attach_proposal_experiment(conn, proposal_id=args.proposal_id, fixture_suite=_fixture_suite_arg(args), experiment_id=args.experiment_id, started_at=args.started_at)
            recommendation = evaluate_promotion_recommendation(conn, args.proposal_id)
        except (ImprovementProposalError, ExperimentError, json.JSONDecodeError, OSError) as error:
            return _fail_closed(ImprovementProposalError(str(error)))
    _json_print({'status': 'ok', 'experiment_result': result, 'recommendation': recommendation})
    return 0

def cmd_improve_review(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = review_improvement_proposal(conn, proposal_id=args.proposal_id, decision=args.decision, reviewer_id=args.reviewer_id, notes=args.notes, reviewed_at=args.reviewed_at)
        except ImprovementProposalError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_improve_promote(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = promote_memory_model_version(conn, proposal_id=args.proposal_id, approved_by=args.approved_by, promoted_at=args.promoted_at)
        except ImprovementProposalError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_improve_rollback(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = rollback_memory_model_promotion(conn, promotion_id=args.promotion_id, reviewer_id=args.reviewer_id, rolled_back_at=args.rolled_back_at)
        except ImprovementProposalError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_improve_status(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        result = improvement_status(conn)
    _json_print(result)
    return 0

def cmd_benchmark_run(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = run_benchmark(conn, suite=args.suite, fixture_root=args.fixture_root, seed=args.seed)
        except BenchmarkError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] == 'passed' else 1

def cmd_benchmark_status(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        result = benchmark_status(conn, limit=args.limit)
    _json_print(result)
    return 0

def cmd_policy_classify(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        result = classify_action(conn, action_class=args.action_class, target_type=args.target_type, target_id=args.target_id)
    _json_print(result)
    return 0 if result['status'] in {'allowed', 'approval_required', 'denied', 'unauthorized', 'unavailable'} else 1

def cmd_policy_approval_needed(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        result = policy_approval_needed_queue(conn, limit=args.limit)
    _json_print(result)
    return 0

def cmd_writeback_snapshot(args: argparse.Namespace) -> int:
    _json_print(snapshot_fixture_root(args.fixture_root))
    return 0

def cmd_writeback_propose(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        result = propose_writeback(conn, fixture_root=args.fixture_root, file_name=args.file, content=args.content, title=args.title)
    _json_print(result)
    return 0 if result['status'] in {'approval_required', 'unauthorized'} else 1

def cmd_writeback_diff(args: argparse.Namespace) -> int:
    result = diff_fixture_file(args.fixture_root, file_name=args.file, proposed_content=args.content)
    _json_print(result)
    return 0 if result['status'] == 'ok' else 1

def cmd_writeback_approve(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = approve_writeback(conn, args.proposal_id)
        except PolicyGuardError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_writeback_dry_run(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = dry_run_writeback(conn, proposal_id=args.proposal_id, fixture_root=args.fixture_root, file_name=args.file)
        except PolicyGuardError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] == 'ok' else 1

def cmd_writeback_write(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = writeback_fixture(conn, proposal_id=args.proposal_id, fixture_root=args.fixture_root, file_name=args.file, expected_after_hash=args.expected_after_hash)
        except PolicyGuardError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] == 'ok' else 1

def cmd_writeback_read_back(args: argparse.Namespace) -> int:
    result = read_back_fixture(args.fixture_root, file_name=args.file)
    _json_print(result)
    return 0 if result['status'] == 'ok' else 1

def cmd_writeback_rollback(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = rollback_fixture(conn, proposal_id=args.proposal_id, fixture_root=args.fixture_root, file_name=args.file, previous_content=args.previous_content)
        except PolicyGuardError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] == 'rolled_back' else 1

def cmd_writeback_tombstone(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = tombstone_writeback(conn, args.proposal_id, reason=args.reason)
        except PolicyGuardError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_health(args: argparse.Namespace) -> int:
    result = open_local_health_report(args.db, repo_root=repo_root(), projection_root=args.projection_root)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded'} else 1

def cmd_service_start(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = service_start(conn, repo_root=repo_root(), projection_root=args.projection_root)
        except ServiceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded'} else 1

def cmd_service_status(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = service_status(conn, repo_root=repo_root(), projection_root=args.projection_root)
        except ServiceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded'} else 1

def cmd_service_stop(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = service_stop(conn, reason=args.reason, repo_root=repo_root(), projection_root=args.projection_root)
        except ServiceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded', 'unavailable'} else 1

def cmd_service_restart(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = service_restart(conn, reason=args.reason, repo_root=repo_root(), projection_root=args.projection_root)
        except ServiceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded'} else 1

def cmd_wiki_generate(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = write_projection(conn, args.output_root)
        except ProjectionError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_wiki_status(args: argparse.Namespace) -> int:
    try:
        result = projection_surface_status(args.output_root)
    except OperatorSurfaceError as error:
        return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_operator_overview(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = operator_overview(conn, query=args.query, projection_root=args.projection_root, limit=args.limit)
        except OperatorSurfaceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_operator_sources(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = operator_source_health(conn)
        except OperatorSurfaceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded'} else 1

def cmd_operator_recall(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = operator_recall_status(conn, args.query, limit=args.limit)
        except OperatorSurfaceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded', 'abstain'} else 1

def cmd_operator_proposals(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = operator_proposals_status(conn, limit=args.limit)
        except OperatorSurfaceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_operator_council(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = operator_council_status(conn, limit=args.limit)
        except OperatorSurfaceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_operator_autonomy(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = operator_autonomy_status(conn, limit=args.limit)
        except OperatorSurfaceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_operator_hermes(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = operator_hermes_status(conn)
        except OperatorSurfaceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_operator_projection(args: argparse.Namespace) -> int:
    try:
        result = projection_surface_status(args.output_root)
    except OperatorSurfaceError as error:
        return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_operator_approval_needed(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = operator_approval_needed(conn, limit=args.limit)
        except OperatorSurfaceError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_operator_scope(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            from .scope import scope_status as operator_scope_status
            result = operator_scope_status(conn, limit=args.limit)
        except ScopeError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_operator_api(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            if args.view == 'index':
                result = operator_api_index(conn, query=args.query, projection_root=args.projection_root, limit=args.limit)
            else:
                result = operator_api_view(conn, args.view, query=args.query, projection_root=args.projection_root, limit=args.limit)
        except (OperatorAPIError, OperatorSurfaceError) as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_hermes_status(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        result = provider_status(conn, profile_id=args.profile_id)
    _json_print(result)
    return 0

def cmd_hermes_tools(args: argparse.Namespace) -> int:
    _json_print(tool_manifest())
    return 0

def cmd_hermes_register_profile(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = register_profile_sources(conn, args.profile_id, args.profile_root)
        except HermesProviderError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded'} else 1

def cmd_hermes_ingest_profile(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = ingest_profile_markdown(conn, args.profile_id, args.profile_root)
        except HermesProviderError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded'} else 1

def cmd_hermes_context(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = context_packet(conn, args.query, profile_id=args.profile_id, limit=args.limit)
        except HermesProviderError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded', 'abstain'} else 1

def cmd_hermes_writeback_status(args: argparse.Namespace) -> int:
    try:
        result = markdown_writeback_status(args.profile_id)
    except HermesProviderError as error:
        return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_hermes_overflow_pressure(args: argparse.Namespace) -> int:
    try:
        result = overflow_pressure_status(args.profile_id, args.fixture_root)
    except HermesProviderError as error:
        return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded', 'unauthorized'} else 1

def cmd_hermes_live_overflow_status(args: argparse.Namespace) -> int:
    try:
        result = live_overflow_status(profile_ids=tuple(args.profile_id or ['default', 'ada', 'adila', 'amara', 'designer', 'lakshmi', 'makeda', 'shifa']), hermes_home=args.hermes_home)
    except LiveOverflowError as error:
        return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'trigger'} else 1

def _automatic_live_overflow_policy_enabled(hermes_home: str | None) -> bool:
    home = Path(hermes_home or os.environ.get('HERMES_HOME') or Path.home() / '.hermes').expanduser()
    config_path = home / 'mnemoir_provenance.json'
    try:
        metadata = os.lstat(config_path)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            return False
        payload = json.loads(config_path.read_text(encoding='utf-8'))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict) and payload.get('writeback_mode') == 'live_overflow_trim'

def cmd_hermes_live_overflow_sweep(args: argparse.Namespace) -> int:
    """Run the bounded policy selected durably in the profile Mnemoir config."""
    if not _automatic_live_overflow_policy_enabled(args.hermes_home):
        return _fail_closed(LiveOverflowError('automatic_live_overflow_policy_not_enabled'))
    try:
        with _open_initialized(args.db) as conn:
            result = run_live_overflow_coordinator(conn, profile_ids=tuple(args.profile_id or ['default']), hermes_home=args.hermes_home, backup_root=args.backup_root)
    except LiveOverflowError as error:
        return _fail_closed(error)
    except sqlite3.Error:
        _json_print({'status': 'error', 'error': 'database_operation_failed'})
        return 1
    _json_print(result)
    return 0 if result['status'] in {'succeeded', 'partial'} else 1

def _load_private_writeback_authorization(value: str) -> WritebackAuthorization:
    path = Path(value)
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise LiveOverflowError('authorization_file_denied') from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.getuid() or (stat.S_IMODE(metadata.st_mode) != 384):
        raise LiveOverflowError('authorization_file_permissions_denied')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, 'r', encoding='utf-8') as handle:
            payload = json.load(handle)
        return WritebackAuthorization(**payload)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise LiveOverflowError('authorization_file_invalid') from exc

def cmd_hermes_live_overflow_trim(args: argparse.Namespace) -> int:
    try:
        authorization = _load_private_writeback_authorization(args.authorization_file)
        with connect(args.db) as conn:
            result = execute_writeback(conn, request_from_authorization(authorization), authorization, backup_root=args.backup_root)
    except LiveOverflowError as error:
        return _fail_closed(error)
    except sqlite3.Error:
        _json_print({'status': 'error', 'error': 'database_operation_failed'})
        return 1
    _json_print(result)
    return 0 if result['state'] == 'completed' else 1

def cmd_hermes_live_overflow_reconcile(args: argparse.Namespace) -> int:
    try:
        authorization = _load_private_writeback_authorization(args.authorization_file)
        with connect(args.db) as conn:
            result = reconcile_writeback(conn, args.operation_id, backup_root=args.backup_root, authorization=authorization)
    except LiveOverflowError as error:
        return _fail_closed(error)
    except sqlite3.Error:
        _json_print({'status': 'error', 'error': 'database_operation_failed'})
        return 1
    _json_print(result)
    return 0 if result['state'] in {'completed', 'failed_before_mutation', 'rolled_back'} else 1

def cmd_hermes_live_overflow_rollback(args: argparse.Namespace) -> int:
    try:
        authorization = _load_private_writeback_authorization(args.authorization_file)
        with connect(args.db) as conn:
            result = rollback_writeback(conn, args.original_operation_id, request_from_authorization(authorization), authorization, backup_root=args.backup_root)
    except LiveOverflowError as error:
        return _fail_closed(error)
    except sqlite3.Error:
        _json_print({'status': 'error', 'error': 'database_operation_failed'})
        return 1
    _json_print(result)
    return 0 if result['state'] == 'rolled_back' else 1

def cmd_hermes_live_overflow_ingest_pending(args: argparse.Namespace) -> int:
    try:
        with connect(args.db) as conn:
            result = ingest_pending_evidence_spools(conn, profile_ids=tuple(args.profile_id) if args.profile_id else None, hermes_home=args.hermes_home, backup_root=args.backup_root, limit=args.limit, dry_run=args.dry_run, keep_pending=args.keep_pending)
    except LiveOverflowError as error:
        return _fail_closed(error)
    except sqlite3.Error as error:
        _json_print({'status': 'error', 'error': str(error)})
        return 1
    _json_print(result)
    return 0 if result['status'] in {'PASS', 'PARTIAL'} else 1

def _source_context_from_args(args: argparse.Namespace) -> dict[str, Any]:
    context = {'objective_id': args.objective_id}
    if getattr(args, 'assignment_id', None):
        context['assignment_id'] = args.assignment_id
    if getattr(args, 'source_context_json', None):
        context.update(json.loads(args.source_context_json))
    return context

def _autonomy_plan_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    return {'objective_id': args.objective_id, 'trigger_type': args.trigger_type, 'action_type': args.action_type, 'idempotency_key': args.idempotency_key, 'objective': args.objective, 'assignment_id': args.assignment_id, 'action_title': args.action_title, 'action_body': args.action_body, 'max_seconds': args.max_seconds, 'max_cost': args.max_cost, 'source_context': _source_context_from_args(args)}

def cmd_autonomy_plan(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = plan_tick(conn, **_autonomy_plan_kwargs(args))
        except (AutonomyError, json.JSONDecodeError) as error:
            return _fail_closed(AutonomyError(str(error)))
    _json_print(result)
    return 0

def cmd_autonomy_run(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            if args.tick_id:
                result = run_tick(conn, tick_id=args.tick_id)
            else:
                result = plan_and_run_tick(conn, **_autonomy_plan_kwargs(args))
        except (AutonomyError, json.JSONDecodeError) as error:
            return _fail_closed(AutonomyError(str(error)))
    _json_print(result)
    return 0 if result['status'] in {'ok', 'deduped', 'approval_required', 'paused', 'cancelled'} else 1

def cmd_autonomy_status(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = autonomy_status(conn, args.tick_id)
        except AutonomyError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_autonomy_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        ticks = list_ticks(conn, status=args.status, limit=args.limit)
    _json_print({'status': 'ok', 'ticks': ticks})
    return 0

def cmd_autonomy_pause(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = pause_tick(conn, args.tick_id, reason=args.reason)
        except AutonomyError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_autonomy_resume(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = resume_tick(conn, args.tick_id, reason=args.reason)
        except AutonomyError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_autonomy_kill(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = kill_tick(conn, args.tick_id, reason=args.reason)
        except AutonomyError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_autonomy_receipts(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = autonomy_receipt(conn, args.tick_id)
        except AutonomyError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_members_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        members = list_members(conn)
    _json_print({'status': 'ok', 'members': members})
    return 0

def cmd_council_members_bind_role(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = bind_role(conn, actor_id=args.actor_id, role=args.role)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_objectives_create(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = create_objective(conn, title=args.title, body=args.body, owner_actor_id=args.owner_actor_id, priority=args.priority)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_objectives_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        objectives = list_objectives(conn, status=args.status, limit=args.limit)
    _json_print({'status': 'ok', 'objectives': objectives})
    return 0

def cmd_council_objectives_show(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = show_objective(conn, args.objective_id)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_objectives_search(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        objectives = search_objectives(conn, args.query, status=args.status, limit=args.limit)
    _json_print({'status': 'ok', 'objectives': objectives})
    return 0

def cmd_council_objectives_close(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = update_objective_status(conn, objective_id=args.objective_id, status='closed', reason=args.reason)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_objectives_block(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = update_objective_status(conn, objective_id=args.objective_id, status='blocked', reason=args.reason)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_assignments_create(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = create_assignment(conn, objective_id=args.objective_id, title=args.title, body=args.body, assigned_actor_id=args.assigned_actor_id, due_at=args.due_at, priority=args.priority)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_assignments_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        assignments = list_assignments(conn, objective_id=args.objective_id, status=args.status, actor_id=args.actor_id, limit=args.limit)
    _json_print({'status': 'ok', 'assignments': assignments})
    return 0

def cmd_council_assignments_status(args: argparse.Namespace, status: str) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = update_assignment_status(conn, assignment_id=args.assignment_id, status=status, reason=args.reason)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_evidence_attach(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = attach_evidence(conn, objective_id=args.objective_id, assignment_id=args.assignment_id, title=args.title, summary=args.summary, refs=refs_from_cli_args(args.ref_type, args.ref_id, args.refs_json))
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_evidence_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        evidence = list_evidence(conn, objective_id=args.objective_id, assignment_id=args.assignment_id, limit=args.limit)
    _json_print({'status': 'ok', 'evidence_packets': evidence})
    return 0

def cmd_council_reviews_record(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = record_review(conn, objective_id=args.objective_id, assignment_id=args.assignment_id, evidence_packet_id=args.evidence_packet_id, reviewer_actor_id=args.reviewer_actor_id, outcome=args.outcome, rationale=args.rationale)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_reviews_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        reviews = list_reviews(conn, objective_id=args.objective_id, outcome=args.outcome, limit=args.limit)
    _json_print({'status': 'ok', 'reviews': reviews})
    return 0

def cmd_council_handoffs_create(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = create_handoff(conn, objective_id=args.objective_id, title=args.title, summary=args.summary, from_actor_id=args.from_actor_id, to_actor_id=args.to_actor_id, compat=args.compat, evidence_packet_ids=csv_from_cli(args.evidence_packet_ids), status=args.status)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_handoffs_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        handoffs = list_handoffs(conn, objective_id=args.objective_id, compat=args.compat, status=args.status, actor_id=args.actor_id, limit=args.limit)
    _json_print({'status': 'ok', 'handoffs': handoffs})
    return 0

def cmd_council_handoffs_show(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = show_handoff(conn, args.handoff_id)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_handoffs_search(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        handoffs = search_handoffs(conn, query=args.query, project_id=args.project_id, compat=args.compat, actor_id=args.actor_id, status=args.status, objective_id=args.objective_id, evidence_packet_id=args.evidence_packet_id, limit=args.limit)
    _json_print({'status': 'ok', 'handoffs': handoffs})
    return 0

def cmd_council_lifecycle_show(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = lifecycle(conn, args.objective_id)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_council_records_create(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = create_record(conn, objective_id=args.objective_id, kind=args.kind, title=args.title, body=args.body, severity=args.severity)
        except CouncilError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_proposals_create(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = create_proposal(conn, **proposal_from_cli_args(args))
        except CurationError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_proposals_list(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        proposals = list_proposals(conn, limit=args.limit)
    _json_print({'status': 'ok', 'proposals': proposals})
    return 0

def cmd_proposals_inspect(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = inspect_proposal(conn, args.proposal_id)
        except CurationError as error:
            return _fail_closed(error)
    _json_print({'status': 'ok', 'proposal': result})
    return 0

def cmd_proposals_action(args: argparse.Namespace) -> int:
    args.action = args.proposal_command
    return cmd_proposals_review(args)

def cmd_plugin_install(args: argparse.Namespace) -> int:
    try:
        result = install_hermes_plugin(args.hermes_home)
    except PluginInstallError as error:
        _json_print({'status': 'error', 'error': str(error)})
        return 1
    _json_print(result)
    return 0

def cmd_worker_enqueue(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = enqueue_promotion(conn, args.proposal_id)
        except WorkerError as error:
            return _fail_closed(ServiceError(str(error)))
    _json_print(result)
    return 0

def cmd_worker_run(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            clear_stop(conn)
            result = run_bounded_worker(conn, batch_limit=args.batch_limit, lease_seconds=args.lease_seconds)
        except WorkerError as error:
            return _fail_closed(ServiceError(str(error)))
    _json_print(result)
    return 0

def cmd_worker_stop(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        result = request_stop(conn, args.reason)
    _json_print(result)
    return 0

def cmd_worker_status(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        result = worker_status(conn, args.limit)
    _json_print(result)
    return 0

def cmd_proposals_review(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = review_proposal(conn, proposal_id=args.proposal_id, action=args.action, reviewer_actor_id=args.reviewer, reason=args.reason, title=args.title, summary=args.summary, body=args.body)
        except CurationError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_memories_write(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = write_memory(conn, proposal_id=args.proposal_id)
        except CurationError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_memories_read(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = read_memory(conn, args.memory_id)
        except CurationError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_memories_tombstone(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = tombstone_memory(conn, memory_id=args.memory_id, reason=args.reason)
        except CurationError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_memories_rollback(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = rollback_memory(conn, memory_id=args.memory_id, version=args.version, reason=args.reason)
        except CurationError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_scores_apply(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = apply_scoring_scenario(conn, memory_id=args.memory_id, scenario=args.scenario, occurred_at=args.occurred_at, related_memory_id=args.related_memory_id, evidence_id=args.evidence_id, weight=args.weight)
        except ScoringError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_scores_inspect(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = {'status': 'ok', 'score_summary': score_summary(conn, args.memory_id)}
        except ScoringError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_scores_history(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            history = score_history(conn, args.memory_id, limit=args.limit)
        except ScoringError as error:
            return _fail_closed(error)
    _json_print({'status': 'ok', 'memory_id': args.memory_id, 'score_history': history})
    return 0

def cmd_scores_queue(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        queue = review_queue(conn, limit=args.limit)
    _json_print({'status': 'ok', 'review_queue': queue})
    return 0

def cmd_scores_rank(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        ranked = ranked_memories(conn, limit=args.limit)
    _json_print({'status': 'ok', 'ranked_memories': ranked})
    return 0

def cmd_scores_decay(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = decay_memory(conn, memory_id=args.memory_id, occurred_at=args.occurred_at)
        except ScoringError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_retrieval_index(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        result = rebuild_retrieval_index(conn)
    _json_print(result)
    return 0

def cmd_retrieval_status(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        result = retrieval_status(conn)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded'} else 1

def cmd_retrieval_search(args: argparse.Namespace) -> int:
    root = repo_root()
    with _open_initialized(args.db) as conn:
        register_sources(conn, root)
        try:
            result = retrieve(conn, args.query, mode=args.mode, limit=args.limit)
        except RetrievalError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded', 'abstain'} else 1

def cmd_retrieval_explain(args: argparse.Namespace) -> int:
    root = repo_root()
    with _open_initialized(args.db) as conn:
        register_sources(conn, root)
        try:
            result = explain(conn, args.query, mode=args.mode, limit=args.limit)
        except RetrievalError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0 if result['status'] in {'ok', 'degraded', 'abstain'} else 1

def cmd_retrieval_feedback(args: argparse.Namespace) -> int:
    with _open_initialized(args.db) as conn:
        try:
            result = record_feedback(conn, query_id=args.query_id, target_type=args.target_type, target_id=args.target_id, rating=args.rating, feedback_text=args.feedback_text)
        except RetrievalError as error:
            return _fail_closed(error)
    _json_print(result)
    return 0

def cmd_ui(args: argparse.Namespace) -> int:
    """Launch the packaged loopback-only local operator application."""
    from .local_ui import serve_ui
    return serve_ui(db_path=args.db, port=args.port, open_browser=not args.no_open)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='mnemoir-provenance', description='Mnemoir Provenance compat 01 read-only source-grounded memory console.')
    parser.add_argument('--db', help='SQLite DB path. Defaults to MNEMOIR_DB or data/mnemoir_provenance.sqlite.')
    sub = parser.add_subparsers(dest='command', required=True)
    ui = sub.add_parser('ui', help='Launch the packaged loopback-only browser operator application.')
    ui.add_argument('--db', default=argparse.SUPPRESS, help='SQLite DB path. Defaults to MNEMOIR_DB or canonical package configuration.')
    ui.add_argument('--port', type=int, default=8765, help='Loopback TCP port; use 0 for an ephemeral port.')
    ui.add_argument('--no-open', action='store_true', help='Do not open the system browser.')
    ui.set_defaults(func=cmd_ui)
    sources = sub.add_parser('sources', help='Register and list configured local sources with health and authority state.')
    sources.set_defaults(func=cmd_sources)
    ingest = sub.add_parser('ingest', help='Ingest real records from configured local repository documentation sources.')
    ingest.add_argument('--limit', type=int, default=25, help='Maximum source records to ingest.')
    ingest.set_defaults(func=cmd_ingest)
    recall_parser = sub.add_parser('recall', help='Run cited lexical, semantic, or hybrid recall over local indexed records.')
    recall_parser.add_argument('query', help='Recall query text.')
    recall_parser.add_argument('--limit', type=int, default=5, help='Maximum cited results to return.')
    recall_parser.add_argument('--mode', choices=['lexical', 'semantic', 'hybrid'], default='lexical', help='Retrieval mode. Semantic/hybrid degrade visibly to lexical-only if the local index is unavailable.')
    recall_parser.set_defaults(func=cmd_recall)
    migration = sub.add_parser('migration', help='compat 15.1 controlled memory migration inventory, dry-run import, scale fixture, and readiness reporting.')
    migration_sub = migration.add_subparsers(dest='migration_command', required=True)
    migration_inventory = migration_sub.add_parser('inventory', help='Inventory controlled migration roots with counts, hashes, classes, and redacted pointers only.')
    migration_inventory.add_argument('--profile-id', required=True)
    migration_inventory.add_argument('--roots', required=True, help='Comma-separated controlled file or directory roots to inventory.')
    migration_inventory.add_argument('--allowed-roots', default='', help='Comma-separated controlled root allowlist.')
    migration_inventory.add_argument('--sample-limit', type=int, default=25)
    migration_inventory.set_defaults(func=cmd_migration_inventory)
    migration_dry_run = migration_sub.add_parser('dry-run', help='Import supplied controlled migration sources and produce a compat 15.2 readiness verdict without live activation.')
    migration_dry_run.add_argument('--profile-id', required=True)
    migration_dry_run.add_argument('--allowed-roots', default='')
    migration_dry_run.add_argument('--honcho-fixture-path')
    migration_dry_run.add_argument('--pre-honcho-memory-root')
    migration_dry_run.add_argument('--session-fixture-path')
    migration_dry_run.add_argument('--obsidian-vault-root')
    migration_dry_run.add_argument('--query', default='durable continuity preference')
    migration_dry_run.set_defaults(func=cmd_migration_dry_run)
    migration_readiness = migration_sub.add_parser('readiness', help='Report compat 15.1 migration/provider/tool/writeback readiness from the current local DB.')
    migration_readiness.add_argument('--profile-id', required=True)
    migration_readiness.add_argument('--query', default='durable continuity preference')
    migration_readiness.add_argument('--context-budget-chars', type=int, default=1200)
    migration_readiness.set_defaults(func=cmd_migration_readiness)
    migration_scale = migration_sub.add_parser('generate-scale', help='Generate deterministic JSONL message-class scale fixture for large-corpus proof.')
    migration_scale.add_argument('--output', required=True)
    migration_scale.add_argument('--records', type=int, default=200000)
    migration_scale.add_argument('--profile-id', default='compat15_1_scale')
    migration_scale.set_defaults(func=cmd_migration_generate_scale)
    migration_import_scale = migration_sub.add_parser('import-scale', help='Streaming import generated JSONL message-class fixture with chunked commits.')
    migration_import_scale.add_argument('--profile-id', required=True)
    migration_import_scale.add_argument('--fixture-path', required=True)
    migration_import_scale.add_argument('--allowed-roots', default='')
    migration_import_scale.add_argument('--chunk-size', type=int, default=5000)
    migration_import_scale.add_argument('--max-records', type=int)
    migration_import_scale.set_defaults(func=cmd_migration_import_scale)
    audit = sub.add_parser('audit', help='List reconstructable ingestion and recall audit receipts.')
    audit.add_argument('--limit', type=int, default=20, help='Maximum audit events to return.')
    audit.set_defaults(func=cmd_audit)
    learning = sub.add_parser('learning', help='compat 15.0.1 learning event/outcome ledger; observation and classification only, no algorithm promotion.')
    learning_sub = learning.add_subparsers(dest='learning_command', required=True)
    learning_record = learning_sub.add_parser('record', help='Record one privacy-safe learning outcome as hash/redacted metadata only.')
    learning_record.add_argument('--event-type', required=True, choices=allowed_learning_event_types())
    learning_record.add_argument('--outcome-label', required=True, choices=allowed_learning_outcome_labels())
    learning_record.add_argument('--failure-class', choices=allowed_learning_failure_classes())
    learning_record.add_argument('--severity', default='info', choices=['info', 'watch', 'warning', 'critical'])
    learning_record.add_argument('--profile-id')
    learning_record.add_argument('--actor-id')
    learning_record.add_argument('--session-id')
    learning_record.add_argument('--query-id')
    learning_record.add_argument('--memory-id')
    learning_record.add_argument('--proposal-id')
    learning_record.add_argument('--source-id')
    learning_record.add_argument('--raw-event-id')
    learning_record.add_argument('--evidence-ids', help='Comma-separated evidence IDs; IDs only, no raw evidence text.')
    learning_record.add_argument('--related-ids-json', help='Leak-safe JSON object of related IDs and labels.')
    learning_record.add_argument('--input-text', help='Optional raw input used only for hashing; raw text is never persisted or returned.')
    learning_record.add_argument('--output-text', help='Optional raw output used only for hashing; raw text is never persisted or returned.')
    learning_record.add_argument('--metadata-json', help='Optional structured metadata; suspicious/private string values are hash-redacted.')
    learning_record.add_argument('--occurred-at')
    learning_record.set_defaults(func=cmd_learning_record)
    learning_list = learning_sub.add_parser('list', help='List learning events with leak-safe hash/redacted fields.')
    learning_list.add_argument('--event-type', choices=allowed_learning_event_types())
    learning_list.add_argument('--outcome-label', choices=allowed_learning_outcome_labels())
    learning_list.add_argument('--failure-class', choices=allowed_learning_failure_classes())
    learning_list.add_argument('--limit', type=int, default=50)
    learning_list.set_defaults(func=cmd_learning_list)
    learning_clusters = learning_sub.add_parser('clusters', help='List deterministic failure clusters; no proposals or promotion behavior.')
    learning_clusters.add_argument('--limit', type=int, default=50)
    learning_clusters.set_defaults(func=cmd_learning_clusters)
    learning_inspect = learning_sub.add_parser('inspect', help='Inspect one learning event by ID.')
    learning_inspect.add_argument('learning_event_id')
    learning_inspect.set_defaults(func=cmd_learning_inspect)
    experiment = sub.add_parser('experiment', help='compat 15.0.2 offline candidate experiment harness; JSON-only, fixture-only, no promotion or live behavior change.')
    experiment_sub = experiment.add_subparsers(dest='experiment_command', required=True)
    experiment_model = experiment_sub.add_parser('model', help='Define or list offline baseline/candidate memory-model versions.')
    experiment_model_sub = experiment_model.add_subparsers(dest='experiment_model_command', required=True)
    experiment_model_define = experiment_model_sub.add_parser('define', help='Persist a baseline or candidate model config with a stable ID and config hash.')
    experiment_model_define.add_argument('--kind', required=True, choices=['baseline', 'candidate'])
    experiment_model_define.add_argument('--config-json', required=True, help='Leak-safe JSON object with deterministic scoring/decay/routing knobs.')
    experiment_model_define.add_argument('--parent-model-version-id')
    experiment_model_define.add_argument('--metadata-json', help='Leak-safe JSON object; private-looking values are hash-redacted.')
    experiment_model_define.add_argument('--created-at')
    experiment_model_define.set_defaults(func=cmd_experiment_model_define)
    experiment_model_list = experiment_model_sub.add_parser('list', help='List offline memory-model versions.')
    experiment_model_list.add_argument('--kind', choices=['baseline', 'candidate'])
    experiment_model_list.add_argument('--status', choices=['baseline', 'candidate', 'rejected', 'experiment_only'])
    experiment_model_list.add_argument('--limit', type=int, default=50)
    experiment_model_list.set_defaults(func=cmd_experiment_model_list)
    experiment_run = experiment_sub.add_parser('run', help='Run a deterministic offline baseline-vs-candidate experiment over safe fixtures.')
    experiment_run.add_argument('--baseline-model-version-id', required=True)
    experiment_run.add_argument('--candidate-model-version-id', required=True)
    experiment_run.add_argument('--fixture-suite-json', help='Leak-safe fixture suite JSON object; omit for built-in safe fixture suite.')
    experiment_run.add_argument('--fixture-suite-path', help='Path to a leak-safe local fixture suite JSON file; no live profiles/vaults/transcripts.')
    experiment_run.add_argument('--metadata-json', help='Leak-safe JSON object for operator metadata.')
    experiment_run.add_argument('--started-at')
    experiment_run.set_defaults(func=cmd_experiment_run)
    experiment_list = experiment_sub.add_parser('list', help='List persisted offline candidate experiments.')
    experiment_list.add_argument('--candidate-model-version-id')
    experiment_list.add_argument('--status', choices=['pass', 'fail', 'blocked', 'error'])
    experiment_list.add_argument('--limit', type=int, default=50)
    experiment_list.set_defaults(func=cmd_experiment_list)
    experiment_inspect = experiment_sub.add_parser('inspect', help='Inspect one experiment plus deterministic leak-safe case rows.')
    experiment_inspect.add_argument('experiment_id')
    experiment_inspect.add_argument('--case-limit', type=int, default=200)
    experiment_inspect.set_defaults(func=cmd_experiment_inspect)
    improve = sub.add_parser('improve', help='compat 15.0.3 self-generated improvement proposals and gated local memory-model promotion; JSON-only, local Mnemoir storage only.')
    improve_sub = improve.add_subparsers(dest='improve_command', required=True)
    improve_propose = improve_sub.add_parser('propose', help='Generate bounded proposals from recurring learning failure clusters.')
    improve_propose.add_argument('--min-cluster-events', type=int, default=2)
    improve_propose.add_argument('--profile-id')
    improve_propose.add_argument('--created-at')
    improve_propose.set_defaults(func=cmd_improve_propose)
    improve_list = improve_sub.add_parser('list', help='List leak-safe improvement proposals.')
    improve_list.add_argument('--status', choices=['draft', 'experiment_ready', 'recommended', 'rejected', 'approved', 'promoted', 'rolled_back', 'blocked'])
    improve_list.add_argument('--limit', type=int, default=50)
    improve_list.set_defaults(func=cmd_improve_list)
    improve_inspect = improve_sub.add_parser('inspect', help='Inspect one proposal by ID.')
    improve_inspect.add_argument('proposal_id')
    improve_inspect.set_defaults(func=cmd_improve_inspect)
    improve_experiment = improve_sub.add_parser('experiment', help='Run or attach a compat 15.0.2 offline experiment, then evaluate recommendation.')
    improve_experiment.add_argument('proposal_id')
    improve_experiment.add_argument('--experiment-id')
    improve_experiment.add_argument('--fixture-suite-json', help='Leak-safe fixture suite JSON object; omit for built-in safe fixture suite.')
    improve_experiment.add_argument('--fixture-suite-path', help='Path to leak-safe local fixture suite JSON; no live profiles/vaults/transcripts.')
    improve_experiment.add_argument('--started-at')
    improve_experiment.set_defaults(func=cmd_improve_experiment)
    improve_review = improve_sub.add_parser('review', help='Approve, reject, or block a recommended proposal before promotion.')
    improve_review.add_argument('proposal_id')
    improve_review.add_argument('--decision', required=True, choices=['approve', 'reject', 'block'])
    improve_review.add_argument('--reviewer-id', default='operator')
    improve_review.add_argument('--notes')
    improve_review.add_argument('--reviewed-at')
    improve_review.set_defaults(func=cmd_improve_review)
    improve_promote = improve_sub.add_parser('promote', help='Promote an explicitly approved proposal as the active local memory-model version.')
    improve_promote.add_argument('proposal_id')
    improve_promote.add_argument('--approved-by', default='operator')
    improve_promote.add_argument('--promoted-at')
    improve_promote.set_defaults(func=cmd_improve_promote)
    improve_rollback = improve_sub.add_parser('rollback', help='Rollback one active local model promotion and restore its prior local model version.')
    improve_rollback.add_argument('promotion_id')
    improve_rollback.add_argument('--reviewer-id', default='operator')
    improve_rollback.add_argument('--rolled-back-at')
    improve_rollback.set_defaults(func=cmd_improve_rollback)
    improve_status = improve_sub.add_parser('status', help='Show proposal/promotion counts and active local model version without live behavior mutation.')
    improve_status.set_defaults(func=cmd_improve_status)
    policy = sub.add_parser('policy', help='compat 10 unified policy classification and approval-needed queue; fail-closed, local DB-backed, no live IO.')
    policy_sub = policy.add_subparsers(dest='policy_command', required=True)
    policy_classify = policy_sub.add_parser('classify', help='Classify a local action class as allowed, approval_required, denied, unauthorized, unavailable, or error and write decision/audit records.')
    policy_classify.add_argument('--action-class', required=True)
    policy_classify.add_argument('--target-type', default='unspecified')
    policy_classify.add_argument('--target-id')
    policy_classify.set_defaults(func=cmd_policy_classify)
    policy_queue = policy_sub.add_parser('approval-needed', help='List approval-required policy decisions and proposals backed by real DB records.')
    policy_queue.add_argument('--limit', type=int, default=50)
    policy_queue.set_defaults(func=cmd_policy_approval_needed)
    writeback = sub.add_parser('writeback', help='compat 10 temporary-fixture Hermes markdown writeback guard; no real profile reads/writes or default MEMORY.md/USER.md authority.', description='compat 10 temporary-fixture Hermes markdown writeback guard. Operates only on caller-supplied temporary fixture roots; no real profile reads/writes and no default MEMORY.md/USER.md write authority.')
    writeback_sub = writeback.add_subparsers(dest='writeback_command', required=True)
    writeback_snapshot = writeback_sub.add_parser('snapshot', help='Hash pre/post state for a caller-supplied temporary fixture root only.')
    writeback_snapshot.add_argument('--fixture-root', required=True)
    writeback_snapshot.set_defaults(func=cmd_writeback_snapshot)
    writeback_propose = writeback_sub.add_parser('propose', help='Create a DB-backed approval-required proposal and diff for a temporary MEMORY.md/USER.md fixture mutation.')
    writeback_propose.add_argument('--fixture-root', required=True)
    writeback_propose.add_argument('--file', required=True, choices=['MEMORY.md', 'USER.md'])
    writeback_propose.add_argument('--content', required=True)
    writeback_propose.add_argument('--title')
    writeback_propose.set_defaults(func=cmd_writeback_propose)
    writeback_diff = writeback_sub.add_parser('diff', help='Show before/after hashes and unified diff without mutation.')
    writeback_diff.add_argument('--fixture-root', required=True)
    writeback_diff.add_argument('--file', required=True, choices=['MEMORY.md', 'USER.md'])
    writeback_diff.add_argument('--content', required=True)
    writeback_diff.set_defaults(func=cmd_writeback_diff)
    writeback_approve = writeback_sub.add_parser('approve', help='Approve a proposed temporary fixture writeback before write.')
    writeback_approve.add_argument('proposal_id')
    writeback_approve.set_defaults(func=cmd_writeback_approve)
    writeback_dry_run = writeback_sub.add_parser('dry-run', help='Recompute diff for an approved/proposed writeback without mutation.')
    writeback_dry_run.add_argument('proposal_id')
    writeback_dry_run.add_argument('--fixture-root', required=True)
    writeback_dry_run.add_argument('--file', required=True, choices=['MEMORY.md', 'USER.md'])
    writeback_dry_run.set_defaults(func=cmd_writeback_dry_run)
    writeback_write = writeback_sub.add_parser('write', help='Write an approved proposal to a temporary fixture, then read back and receipt hashes.')
    writeback_write.add_argument('proposal_id')
    writeback_write.add_argument('--fixture-root', required=True)
    writeback_write.add_argument('--file', required=True, choices=['MEMORY.md', 'USER.md'])
    writeback_write.add_argument('--expected-after-hash')
    writeback_write.set_defaults(func=cmd_writeback_write)
    writeback_read = writeback_sub.add_parser('read-back', help='Read back a temporary fixture file with hash metadata.')
    writeback_read.add_argument('--fixture-root', required=True)
    writeback_read.add_argument('--file', required=True, choices=['MEMORY.md', 'USER.md'])
    writeback_read.set_defaults(func=cmd_writeback_read_back)
    writeback_rollback = writeback_sub.add_parser('rollback', help='Restore caller-provided previous content to a temporary fixture and receipt it.')
    writeback_rollback.add_argument('proposal_id')
    writeback_rollback.add_argument('--fixture-root', required=True)
    writeback_rollback.add_argument('--file', required=True, choices=['MEMORY.md', 'USER.md'])
    writeback_rollback.add_argument('--previous-content', required=True)
    writeback_rollback.set_defaults(func=cmd_writeback_rollback)
    writeback_tombstone = writeback_sub.add_parser('tombstone', help='Tombstone a proposal record without deleting fixture bytes.')
    writeback_tombstone.add_argument('proposal_id')
    writeback_tombstone.add_argument('--reason', default='operator_tombstone')
    writeback_tombstone.set_defaults(func=cmd_writeback_tombstone)
    health = sub.add_parser('health', help='compat 09 leak-safe local health spine over DB, sources, policy, retrieval, Council, autonomy, Hermes, and projection readiness.', description='compat 09 health spine: leak-safe local DB/source/policy/retrieval/Council/autonomy/Hermes/projection readiness.')
    health.add_argument('--projection-root', help='Optional caller-supplied derived projection root to inspect; no canonical writeback.')
    health.set_defaults(func=cmd_health)
    service = sub.add_parser('service', help='compat 09 local managed runtime lifecycle; no autostart, cron, systemd, gateway, provider, credential, permission, or network changes.')
    service_sub = service.add_subparsers(dest='service_command', required=True)
    service_start_parser = service_sub.add_parser('start', help='Start or mark running the local DB-backed managed runtime after fail-closed health checks.')
    service_start_parser.add_argument('--projection-root')
    service_start_parser.set_defaults(func=cmd_service_start)
    service_status_parser = service_sub.add_parser('status', help='Show local service state plus health spine.')
    service_status_parser.add_argument('--projection-root')
    service_status_parser.set_defaults(func=cmd_service_status)
    service_stop_parser = service_sub.add_parser('stop', help='Gracefully stop the local DB-backed managed runtime.')
    service_stop_parser.add_argument('--reason', default='operator_stop')
    service_stop_parser.add_argument('--projection-root')
    service_stop_parser.set_defaults(func=cmd_service_stop)
    service_restart_parser = service_sub.add_parser('restart', help='Stop then start the local managed runtime and prove persisted lifecycle state.')
    service_restart_parser.add_argument('--reason', default='operator_restart')
    service_restart_parser.add_argument('--projection-root')
    service_restart_parser.set_defaults(func=cmd_service_restart)
    plugin = sub.add_parser('plugin', help='Install the packaged Hermes memory-provider payload into an explicit synthetic HERMES_HOME.')
    plugin_sub = plugin.add_subparsers(dest='plugin_command', required=True)
    plugin_install = plugin_sub.add_parser('install', help='Materialize the installed plugin payload; does not edit config or restart Hermes.')
    plugin_install.add_argument('--hermes-home', required=True)
    plugin_install.set_defaults(func=cmd_plugin_install)
    worker = sub.add_parser('worker', help='Explicit bounded durable lifecycle worker; no daemon or autostart.')
    worker_sub = worker.add_subparsers(dest='worker_command', required=True)
    worker_enqueue = worker_sub.add_parser('enqueue')
    worker_enqueue.add_argument('proposal_id')
    worker_enqueue.set_defaults(func=cmd_worker_enqueue)
    worker_run = worker_sub.add_parser('run')
    worker_run.add_argument('--batch-limit', type=int, default=10)
    worker_run.add_argument('--lease-seconds', type=int, default=60)
    worker_run.set_defaults(func=cmd_worker_run)
    worker_stop = worker_sub.add_parser('stop')
    worker_stop.add_argument('--reason', default='operator_stop')
    worker_stop.set_defaults(func=cmd_worker_stop)
    worker_status_parser = worker_sub.add_parser('status')
    worker_status_parser.add_argument('--limit', type=int, default=20)
    worker_status_parser.set_defaults(func=cmd_worker_status)
    proposals = sub.add_parser('proposals', help='Create, list, inspect, approve, edit, or reject memory proposals.')
    proposal_sub = proposals.add_subparsers(dest='proposal_command', required=True)
    proposals_create = proposal_sub.add_parser('create', help='Create a source-grounded candidate memory proposal.')
    proposals_create.add_argument('--title', required=True)
    proposals_create.add_argument('--summary', required=True)
    proposals_create.add_argument('--body', required=True)
    proposals_create.add_argument('--evidence-ids', default='', help='Comma-separated evidence IDs backing the proposal.')
    proposals_create.add_argument('--source-event-ids', default='', help='Comma-separated raw event IDs backing the proposal.')
    proposals_create.add_argument('--target-source-id', default='mnemoir_provenance_canonical')
    proposals_create.add_argument('--memory-id', help='Existing memory ID when proposing a revision.')
    proposals_create.add_argument('--memory-type', default='semantic')
    proposals_create.add_argument('--scope', default='global')
    proposals_create.add_argument('--privacy-class', default='private')
    proposals_create.set_defaults(func=cmd_proposals_create)
    proposals_list = proposal_sub.add_parser('list', help='List memory proposals.')
    proposals_list.add_argument('--limit', type=int, default=20)
    proposals_list.set_defaults(func=cmd_proposals_list)
    proposals_inspect = proposal_sub.add_parser('inspect', help='Inspect one proposal with evidence and source-event references.')
    proposals_inspect.add_argument('proposal_id')
    proposals_inspect.set_defaults(func=cmd_proposals_inspect)
    for action_name in ('approve', 'edit', 'reject'):
        action_parser = proposal_sub.add_parser(action_name, help=f'Explicitly {action_name} one proposal.')
        action_parser.add_argument('proposal_id')
        action_parser.add_argument('--reviewer', required=True, help='Existing active human/agent actor ID performing the review.')
        action_parser.add_argument('--reason')
        action_parser.add_argument('--title')
        action_parser.add_argument('--summary')
        action_parser.add_argument('--body')
        action_parser.set_defaults(func=cmd_proposals_action)
    proposals_review = proposal_sub.add_parser('review', help='Approve, edit, or reject a memory proposal.')
    proposals_review.add_argument('proposal_id')
    proposals_review.add_argument('--action', required=True, choices=['approve', 'edit', 'reject'])
    proposals_review.add_argument('--reviewer', required=True, help='Existing active human/agent actor ID performing the review.')
    proposals_review.add_argument('--reason')
    proposals_review.add_argument('--title')
    proposals_review.add_argument('--summary')
    proposals_review.add_argument('--body')
    proposals_review.set_defaults(func=cmd_proposals_review)
    memories = sub.add_parser('memories', help='Write, read, tombstone, or rollback curated memories.')
    memory_sub = memories.add_subparsers(dest='memory_command', required=True)
    memories_write = memory_sub.add_parser('write', help='Write an approved proposal into canonical memory storage.')
    memories_write.add_argument('proposal_id')
    memories_write.set_defaults(func=cmd_memories_write)
    memories_promote = memory_sub.add_parser('promote', help='Transactionally promote an approved proposal into canonical memory.')
    memories_promote.add_argument('proposal_id')
    memories_promote.set_defaults(func=cmd_memories_write)
    memories_read = memory_sub.add_parser('read', help='Read back a memory with versions, evidence, and lifecycle receipts.')
    memories_read.add_argument('memory_id')
    memories_read.set_defaults(func=cmd_memories_read)
    memories_tombstone = memory_sub.add_parser('tombstone', help='Tombstone a memory without physical erasure.')
    memories_tombstone.add_argument('memory_id')
    memories_tombstone.add_argument('--reason', default='operator_tombstone')
    memories_tombstone.set_defaults(func=cmd_memories_tombstone)
    memories_rollback = memory_sub.add_parser('rollback', help='Restore a prior memory version/state and write receipts.')
    memories_rollback.add_argument('memory_id')
    memories_rollback.add_argument('--version', type=int, required=True)
    memories_rollback.add_argument('--reason', default='operator_rollback')
    memories_rollback.set_defaults(func=cmd_memories_rollback)
    scores = sub.add_parser('scores', help='Apply and inspect deterministic adaptive memory scoring.')
    score_sub = scores.add_subparsers(dest='score_command', required=True)
    scores_apply = score_sub.add_parser('apply', help='Apply a deterministic scoring scenario to a memory.')
    scores_apply.add_argument('memory_id')
    scores_apply.add_argument('--scenario', required=True, choices=['duplicate_fact', 'correction', 'contradiction', 'repeated_preference', 'stale_project_state', 'retrieval_success', 'unsupported_hot_signal', 'weak_signal', 'decay'])
    scores_apply.add_argument('--occurred-at', dest='occurred_at')
    scores_apply.add_argument('--related-memory-id')
    scores_apply.add_argument('--evidence-id')
    scores_apply.add_argument('--weight', type=float, default=1.0)
    scores_apply.set_defaults(func=cmd_scores_apply)
    scores_inspect = score_sub.add_parser('inspect', help='Inspect score state, review pressure, and heat-is-not-truth flags.')
    scores_inspect.add_argument('memory_id')
    scores_inspect.set_defaults(func=cmd_scores_inspect)
    scores_history = score_sub.add_parser('history', help='List persisted score history/audit receipts for a memory.')
    scores_history.add_argument('memory_id')
    scores_history.add_argument('--limit', type=int, default=20)
    scores_history.set_defaults(func=cmd_scores_history)
    scores_queue = score_sub.add_parser('queue', help='List memories requiring review, suppression, or consolidation.')
    scores_queue.add_argument('--limit', type=int, default=20)
    scores_queue.set_defaults(func=cmd_scores_queue)
    scores_rank = score_sub.add_parser('rank', help='List score-aware memory ordering without semantic/vector retrieval.')
    scores_rank.add_argument('--limit', type=int, default=20)
    scores_rank.set_defaults(func=cmd_scores_rank)
    scores_decay = score_sub.add_parser('decay', help='Apply deterministic cooling/decay at a fixed timestamp.')
    scores_decay.add_argument('memory_id')
    scores_decay.add_argument('--occurred-at', required=True)
    scores_decay.set_defaults(func=cmd_scores_decay)
    retrieval = sub.add_parser('retrieval', help='Build, inspect, and query local compat 04 hybrid retrieval indexes.')
    retrieval_sub = retrieval.add_subparsers(dest='retrieval_command', required=True)
    retrieval_index = retrieval_sub.add_parser('index', help='Rebuild deterministic local chunks and embeddings with audit receipts.')
    retrieval_index.set_defaults(func=cmd_retrieval_index)
    retrieval_status_parser = retrieval_sub.add_parser('status', help='Inspect local embedding model and index status.')
    retrieval_status_parser.set_defaults(func=cmd_retrieval_status)
    retrieval_search = retrieval_sub.add_parser('search', help='Run lexical, semantic, or hybrid retrieval with cited explanations.')
    retrieval_search.add_argument('query')
    retrieval_search.add_argument('--mode', choices=['lexical', 'semantic', 'hybrid'], default='hybrid')
    retrieval_search.add_argument('--limit', type=int, default=5)
    retrieval_search.set_defaults(func=cmd_retrieval_search)
    retrieval_explain = retrieval_sub.add_parser('explain', help='Return ranking explanations for a retrieval query.')
    retrieval_explain.add_argument('query')
    retrieval_explain.add_argument('--mode', choices=['lexical', 'semantic', 'hybrid'], default='hybrid')
    retrieval_explain.add_argument('--limit', type=int, default=5)
    retrieval_explain.set_defaults(func=cmd_retrieval_explain)
    retrieval_feedback = retrieval_sub.add_parser('feedback', help='Record local retrieval feedback for an existing query/result.')
    retrieval_feedback.add_argument('query_id')
    retrieval_feedback.add_argument('--target-type', required=True)
    retrieval_feedback.add_argument('--target-id', required=True)
    retrieval_feedback.add_argument('--rating', type=int, required=True)
    retrieval_feedback.add_argument('--feedback-text')
    retrieval_feedback.set_defaults(func=cmd_retrieval_feedback)
    autonomy = sub.add_parser('autonomy', help='Plan, run, inspect, pause, resume, kill, and reconstruct bounded local autonomy ticks.')
    autonomy_sub = autonomy.add_subparsers(dest='autonomy_command', required=True)

    def add_tick_plan_args(p: argparse.ArgumentParser, *, objective_required: bool=True, idempotency_required: bool=True) -> None:
        p.add_argument('--objective-id', required=objective_required)
        p.add_argument('--trigger-type', choices=['manual', 'schedule', 'source_change', 'policy', 'benchmark', 'recovery'], default='manual')
        p.add_argument('--action-type', default='council_record_create')
        p.add_argument('--idempotency-key', required=idempotency_required)
        p.add_argument('--objective')
        p.add_argument('--assignment-id')
        p.add_argument('--action-title')
        p.add_argument('--action-body')
        p.add_argument('--source-context-json')
        p.add_argument('--max-seconds', type=int, default=30)
        p.add_argument('--max-cost', type=float, default=0.0)
    autonomy_plan = autonomy_sub.add_parser('plan', help='Create one bounded tick plan without executing it.')
    add_tick_plan_args(autonomy_plan)
    autonomy_plan.set_defaults(func=cmd_autonomy_plan)
    autonomy_run = autonomy_sub.add_parser('run', help='Run an existing tick or create and run one bounded local tick.')
    autonomy_run.add_argument('--tick-id')
    add_tick_plan_args(autonomy_run, objective_required=False, idempotency_required=False)
    autonomy_run.set_defaults(func=cmd_autonomy_run)
    autonomy_status_parser = autonomy_sub.add_parser('status', help='Show one bounded autonomy tick.')
    autonomy_status_parser.add_argument('tick_id')
    autonomy_status_parser.set_defaults(func=cmd_autonomy_status)
    autonomy_list_parser = autonomy_sub.add_parser('list', help='List bounded autonomy ticks.')
    autonomy_list_parser.add_argument('--status')
    autonomy_list_parser.add_argument('--limit', type=int, default=20)
    autonomy_list_parser.set_defaults(func=cmd_autonomy_list)
    autonomy_pause = autonomy_sub.add_parser('pause', help='Pause a planned/running tick before execution.')
    autonomy_pause.add_argument('tick_id')
    autonomy_pause.add_argument('--reason', default='operator_pause')
    autonomy_pause.set_defaults(func=cmd_autonomy_pause)
    autonomy_resume = autonomy_sub.add_parser('resume', help='Resume a paused tick back to planned status.')
    autonomy_resume.add_argument('tick_id')
    autonomy_resume.add_argument('--reason', default='operator_resume')
    autonomy_resume.set_defaults(func=cmd_autonomy_resume)
    autonomy_kill = autonomy_sub.add_parser('kill', help='Cancel a tick before execution.')
    autonomy_kill.add_argument('tick_id')
    autonomy_kill.add_argument('--reason', default='operator_kill')
    autonomy_kill.set_defaults(func=cmd_autonomy_kill)
    autonomy_receipts = autonomy_sub.add_parser('receipts', help='Reconstruct tick receipt and audit chain.')
    autonomy_receipts.add_argument('tick_id')
    autonomy_receipts.set_defaults(func=cmd_autonomy_receipts)
    council = sub.add_parser('council', help='Inspect and mutate local compat 05 Council state/evidence lifecycle records.')
    council_sub = council.add_subparsers(dest='council_command', required=True)
    council_members = council_sub.add_parser('members', help='List or bind leak-safe Council member roles.')
    council_members_sub = council_members.add_subparsers(dest='members_command', required=True)
    council_members_list = council_members_sub.add_parser('list', help='List Council actor/persona role bindings without profile internals.')
    council_members_list.set_defaults(func=cmd_council_members_list)
    council_members_bind = council_members_sub.add_parser('bind-role', help='Bind an existing actor to a Council role.')
    council_members_bind.add_argument('--actor-id', required=True)
    council_members_bind.add_argument('--role', required=True)
    council_members_bind.set_defaults(func=cmd_council_members_bind_role)
    council_objectives = council_sub.add_parser('objectives', help='Create, list, show, search, close, or block Council objectives.')
    council_objectives_sub = council_objectives.add_subparsers(dest='objectives_command', required=True)
    objectives_create = council_objectives_sub.add_parser('create', help='Create a persistent Council objective.')
    objectives_create.add_argument('--title', required=True)
    objectives_create.add_argument('--body', required=True)
    objectives_create.add_argument('--owner-actor-id')
    objectives_create.add_argument('--priority', type=int, default=0)
    objectives_create.set_defaults(func=cmd_council_objectives_create)
    objectives_list = council_objectives_sub.add_parser('list', help='List Council objectives.')
    objectives_list.add_argument('--status')
    objectives_list.add_argument('--limit', type=int, default=20)
    objectives_list.set_defaults(func=cmd_council_objectives_list)
    objectives_show = council_objectives_sub.add_parser('show', help='Show one Council objective.')
    objectives_show.add_argument('objective_id')
    objectives_show.set_defaults(func=cmd_council_objectives_show)
    objectives_search = council_objectives_sub.add_parser('search', help='Search Council objectives by title/body.')
    objectives_search.add_argument('query')
    objectives_search.add_argument('--status')
    objectives_search.add_argument('--limit', type=int, default=20)
    objectives_search.set_defaults(func=cmd_council_objectives_search)
    objectives_close = council_objectives_sub.add_parser('close', help='Close a Council objective while preserving reviews/dissent.')
    objectives_close.add_argument('objective_id')
    objectives_close.add_argument('--reason', required=True)
    objectives_close.set_defaults(func=cmd_council_objectives_close)
    objectives_block = council_objectives_sub.add_parser('block', help='Mark a Council objective blocked.')
    objectives_block.add_argument('objective_id')
    objectives_block.add_argument('--reason', required=True)
    objectives_block.set_defaults(func=cmd_council_objectives_block)
    council_assignments = council_sub.add_parser('assignments', help='Create, list, claim, complete, or block assignments.')
    council_assignments_sub = council_assignments.add_subparsers(dest='assignments_command', required=True)
    assignments_create = council_assignments_sub.add_parser('create', help='Create an objective-linked assignment.')
    assignments_create.add_argument('--objective-id', required=True)
    assignments_create.add_argument('--title', required=True)
    assignments_create.add_argument('--body', required=True)
    assignments_create.add_argument('--assigned-actor-id', required=True)
    assignments_create.add_argument('--due-at')
    assignments_create.add_argument('--priority', type=int, default=0)
    assignments_create.set_defaults(func=cmd_council_assignments_create)
    assignments_list = council_assignments_sub.add_parser('list', help='List assignments.')
    assignments_list.add_argument('--objective-id')
    assignments_list.add_argument('--status')
    assignments_list.add_argument('--actor-id')
    assignments_list.add_argument('--limit', type=int, default=20)
    assignments_list.set_defaults(func=cmd_council_assignments_list)
    for command_name, status_value in [('claim', 'claimed'), ('complete', 'complete'), ('block', 'blocked')]:
        parser_item = council_assignments_sub.add_parser(command_name, help=f'Set assignment status to {status_value}.')
        parser_item.add_argument('assignment_id')
        parser_item.add_argument('--reason', required=True)
        parser_item.set_defaults(func=lambda args, sv=status_value: cmd_council_assignments_status(args, sv))
    council_evidence = council_sub.add_parser('evidence', help='Attach and list source-backed evidence packets.')
    council_evidence_sub = council_evidence.add_subparsers(dest='evidence_command', required=True)
    evidence_attach = council_evidence_sub.add_parser('attach', help='Attach source-backed evidence to an objective/assignment.')
    evidence_attach.add_argument('--objective-id', required=True)
    evidence_attach.add_argument('--assignment-id')
    evidence_attach.add_argument('--title', required=True)
    evidence_attach.add_argument('--summary', required=True)
    evidence_attach.add_argument('--ref-type', choices=['evidence', 'raw_event', 'memory', 'retrieval_query', 'audit', 'artifact'])
    evidence_attach.add_argument('--ref-id')
    evidence_attach.add_argument('--refs-json', help='JSON list of {ref_type, ref_id, role} evidence references.')
    evidence_attach.set_defaults(func=cmd_council_evidence_attach)
    evidence_list = council_evidence_sub.add_parser('list', help='List evidence packets.')
    evidence_list.add_argument('--objective-id')
    evidence_list.add_argument('--assignment-id')
    evidence_list.add_argument('--limit', type=int, default=20)
    evidence_list.set_defaults(func=cmd_council_evidence_list)
    council_reviews = council_sub.add_parser('reviews', help='Record and list review/verdict rows including veto/dissent.')
    council_reviews_sub = council_reviews.add_subparsers(dest='reviews_command', required=True)
    reviews_record = council_reviews_sub.add_parser('record', help='Record a Council review/verdict row.')
    reviews_record.add_argument('--objective-id', required=True)
    reviews_record.add_argument('--assignment-id')
    reviews_record.add_argument('--evidence-packet-id')
    reviews_record.add_argument('--reviewer-actor-id', required=True)
    reviews_record.add_argument('--outcome', required=True, choices=['approve', 'revise', 'reject', 'veto', 'blocked', 'handoff_required', 'abstain'])
    reviews_record.add_argument('--rationale', required=True)
    reviews_record.set_defaults(func=cmd_council_reviews_record)
    reviews_list = council_reviews_sub.add_parser('list', help='List reviews/verdicts.')
    reviews_list.add_argument('--objective-id')
    reviews_list.add_argument('--outcome')
    reviews_list.add_argument('--limit', type=int, default=20)
    reviews_list.set_defaults(func=cmd_council_reviews_list)
    council_records = council_sub.add_parser('records', help='Create blocker/risk/decision/proposal records.')
    council_records_sub = council_records.add_subparsers(dest='records_command', required=True)
    records_create = council_records_sub.add_parser('create', help='Create a durable Council blocker/risk/decision/proposal record.')
    records_create.add_argument('--objective-id', required=True)
    records_create.add_argument('--kind', required=True, choices=['blocker', 'risk', 'decision', 'proposal'])
    records_create.add_argument('--title', required=True)
    records_create.add_argument('--body', required=True)
    records_create.add_argument('--severity', choices=['low', 'medium', 'high', 'critical'])
    records_create.set_defaults(func=cmd_council_records_create)
    council_handoffs = council_sub.add_parser('handoffs', help='Create, list, show, and search handoffs.')
    council_handoffs_sub = council_handoffs.add_subparsers(dest='handoffs_command', required=True)
    handoffs_create = council_handoffs_sub.add_parser('create', help='Create a searchable handoff linked to objective/evidence.')
    handoffs_create.add_argument('--objective-id', required=True)
    handoffs_create.add_argument('--title', required=True)
    handoffs_create.add_argument('--summary', required=True)
    handoffs_create.add_argument('--from-actor-id', required=True)
    handoffs_create.add_argument('--to-actor-id')
    handoffs_create.add_argument('--phase')
    handoffs_create.add_argument('--status', default='ready')
    handoffs_create.add_argument('--evidence-packet-ids', default='')
    handoffs_create.set_defaults(func=cmd_council_handoffs_create)
    handoffs_list = council_handoffs_sub.add_parser('list', help='List handoffs.')
    handoffs_list.add_argument('--objective-id')
    handoffs_list.add_argument('--phase')
    handoffs_list.add_argument('--status')
    handoffs_list.add_argument('--actor-id')
    handoffs_list.add_argument('--limit', type=int, default=20)
    handoffs_list.set_defaults(func=cmd_council_handoffs_list)
    handoffs_show = council_handoffs_sub.add_parser('show', help='Show a handoff.')
    handoffs_show.add_argument('handoff_id')
    handoffs_show.set_defaults(func=cmd_council_handoffs_show)
    handoffs_search = council_handoffs_sub.add_parser('search', help='Search handoffs by project/phase/actor/status/objective/evidence.')
    handoffs_search.add_argument('--query')
    handoffs_search.add_argument('--project-id')
    handoffs_search.add_argument('--phase')
    handoffs_search.add_argument('--actor-id')
    handoffs_search.add_argument('--status')
    handoffs_search.add_argument('--objective-id')
    handoffs_search.add_argument('--evidence-packet-id')
    handoffs_search.add_argument('--limit', type=int, default=20)
    handoffs_search.set_defaults(func=cmd_council_handoffs_search)
    council_lifecycle = council_sub.add_parser('lifecycle', help='Reconstruct objective lifecycle from local DB state.')
    council_lifecycle_sub = council_lifecycle.add_subparsers(dest='lifecycle_command', required=True)
    lifecycle_show = council_lifecycle_sub.add_parser('show', help='Show objective -> assignment -> evidence -> review/verdict -> handoff lifecycle.')
    lifecycle_show.add_argument('objective_id')
    lifecycle_show.set_defaults(func=cmd_council_lifecycle_show)
    wiki = sub.add_parser('wiki', help='Generate and inspect compat 08 derived non-canonical Obsidian/LLM Wiki projection pages; no writeback.')
    wiki_sub = wiki.add_subparsers(dest='wiki_command', required=True)
    wiki_generate = wiki_sub.add_parser('generate', help='Generate derived markdown pages under a caller-supplied output root.')
    wiki_generate.add_argument('--output-root', required=True, help='Caller-supplied projection directory; temporary roots are preferred in tests.')
    wiki_generate.set_defaults(func=cmd_wiki_generate)
    wiki_status = wiki_sub.add_parser('status', help='Inspect projection manifest status without writing canonical storage.')
    wiki_status.add_argument('--output-root')
    wiki_status.set_defaults(func=cmd_wiki_status)
    operator = sub.add_parser('operator', help='Local compat 08 operator surface aggregating real backend records; no mock dashboard state.')
    operator_sub = operator.add_subparsers(dest='operator_command', required=True)
    operator_overview_parser = operator_sub.add_parser('overview', help='Aggregate sources, recall, proposals, Council, autonomy, Hermes, projection, and approvals.')
    operator_overview_parser.add_argument('--query', default='Council memory')
    operator_overview_parser.add_argument('--projection-root')
    operator_overview_parser.add_argument('--limit', type=int, default=5)
    operator_overview_parser.set_defaults(func=cmd_operator_overview)
    operator_sources_parser = operator_sub.add_parser('sources', help='Show source health and degraded/fail-closed source posture.')
    operator_sources_parser.set_defaults(func=cmd_operator_sources)
    operator_recall_parser = operator_sub.add_parser('recall', help='Run cited local recall through the operator surface.')
    operator_recall_parser.add_argument('query')
    operator_recall_parser.add_argument('--limit', type=int, default=5)
    operator_recall_parser.set_defaults(func=cmd_operator_recall)
    operator_proposals_parser = operator_sub.add_parser('proposals', help='List memory proposals and approval-needed proposal rows.')
    operator_proposals_parser.add_argument('--limit', type=int, default=20)
    operator_proposals_parser.set_defaults(func=cmd_operator_proposals)
    operator_council_parser = operator_sub.add_parser('council', help='Aggregate Council queue, reviews, records, and handoffs from backend records.')
    operator_council_parser.add_argument('--limit', type=int, default=50)
    operator_council_parser.set_defaults(func=cmd_operator_council)
    operator_autonomy_parser = operator_sub.add_parser('autonomy', help='Aggregate autonomy receipts, failures, and approval-required ticks.')
    operator_autonomy_parser.add_argument('--limit', type=int, default=50)
    operator_autonomy_parser.set_defaults(func=cmd_operator_autonomy)
    operator_hermes_parser = operator_sub.add_parser('hermes', help='Show Hermes provider/markdown-source status with no profile markdown reads or writeback.')
    operator_hermes_parser.set_defaults(func=cmd_operator_hermes)
    operator_projection_parser = operator_sub.add_parser('projection', help='Show projection manifest status.')
    operator_projection_parser.add_argument('--output-root')
    operator_projection_parser.set_defaults(func=cmd_operator_projection)
    operator_approval_parser = operator_sub.add_parser('approval-needed', help='List local items requiring operator approval or attention.')
    operator_approval_parser.add_argument('--limit', type=int, default=50)
    operator_approval_parser.set_defaults(func=cmd_operator_approval_needed)
    operator_scope_parser = operator_sub.add_parser('scope', help='compat 11 scoped actor/profile/session/project visibility decisions and audit receipts.')
    operator_scope_parser.add_argument('--limit', type=int, default=50)
    operator_scope_parser.set_defaults(func=cmd_operator_scope)
    operator_api_parser = operator_sub.add_parser('api', help='compat 11 local machine-readable operator API; no remote/public surface.')
    operator_api_parser.add_argument('view', choices=['index', 'overview', 'sources', 'recall', 'proposals', 'council', 'autonomy', 'hermes', 'projection', 'approval-needed', 'scope'])
    operator_api_parser.add_argument('--query', default='Council memory')
    operator_api_parser.add_argument('--projection-root')
    operator_api_parser.add_argument('--limit', type=int, default=20)
    operator_api_parser.set_defaults(func=cmd_operator_api)
    benchmark = sub.add_parser('benchmark', help='Local benchmark/evaluation harness; synthetic/caller-supplied fixtures plus authorized real external/provider benchmark evidence, no public readiness claims.', description='compat 12/13 benchmark harness: local deterministic synthetic/caller-supplied fixtures plus authorized compat 13.9 real quantitative LongMemEval-S, compat 13.10 external-framework execution, compat 13.11 non-provider scorer improvement, and compat 13.12 OpenRouter provider-eval spike; no real Hermes profile markdown or public release execution claims.')
    benchmark_sub = benchmark.add_subparsers(dest='benchmark_command', required=True)
    benchmark_run = benchmark_sub.add_parser('run', help='Run a local benchmark suite and persist dataset/case/run/result rows.')
    benchmark_run.add_argument('--suite', default='smoke', choices=['smoke', 'release-candidate', 'rc', 'industry-metric', 'industry', 'external-adapter', 'external-adapter-audit', 'external', 'external-real', 'real-external', 'longmemeval-real', 'longmemeval-s', 'external-quantitative', 'longmemeval-quantitative', 'external-framework', 'framework-external', 'compat13-10', 'option-b', 'external-improvement', 'non-provider-improvement', 'compat13-11', 'scorer-improvement', 'provider-eval', 'openrouter-provider-eval', 'compat13-12', 'llm-judge'])
    benchmark_run.add_argument('--fixture-root', help='Optional caller-supplied local synthetic fixture root; real Hermes profiles are prohibited.')
    benchmark_run.add_argument('--seed', default='compat12-smoke-seed')
    benchmark_run.add_argument('--report-json', action='store_true', help='Emit the machine-readable JSON report; retained for explicit CLI contract.')
    benchmark_run.set_defaults(func=cmd_benchmark_run)
    benchmark_status_parser = benchmark_sub.add_parser('status', help='List persisted local benchmark runs from canonical DB rows.')
    benchmark_status_parser.add_argument('--limit', type=int, default=10)
    benchmark_status_parser.set_defaults(func=cmd_benchmark_status)
    hermes = sub.add_parser('hermes', help='Inspect and exercise compat 07 mnemoir_local Hermes provider/context/tool surface.')
    hermes_sub = hermes.add_subparsers(dest='hermes_command', required=True)
    hermes_status = hermes_sub.add_parser('status', help='Show mnemoir_local provider status and redacted Hermes markdown source health.')
    hermes_status.add_argument('--profile-id')
    hermes_status.set_defaults(func=cmd_hermes_status)
    hermes_tools = hermes_sub.add_parser('tools', help='List leak-safe local provider tools without touching Hermes config.')
    hermes_tools.set_defaults(func=cmd_hermes_tools)
    hermes_register = hermes_sub.add_parser('register-profile', help='Register explicit temp-profile MEMORY.md/USER.md as read-only redacted sources.')
    hermes_register.add_argument('--profile-id', required=True)
    hermes_register.add_argument('--profile-root', required=True)
    hermes_register.set_defaults(func=cmd_hermes_register_profile)
    hermes_ingest = hermes_sub.add_parser('ingest-profile', help='Read-only ingest explicit temp-profile MEMORY.md/USER.md overflow blocks.')
    hermes_ingest.add_argument('--profile-id', required=True)
    hermes_ingest.add_argument('--profile-root', required=True)
    hermes_ingest.set_defaults(func=cmd_hermes_ingest_profile)
    hermes_context = hermes_sub.add_parser('context', help='Generate a cited mnemoir_local context packet.')
    hermes_context.add_argument('query')
    hermes_context.add_argument('--profile-id')
    hermes_context.add_argument('--limit', type=int, default=5)
    hermes_context.set_defaults(func=cmd_hermes_context)
    hermes_writeback = hermes_sub.add_parser('writeback-status', help='Report default denied/propose_only Hermes markdown writeback posture.')
    hermes_writeback.add_argument('--profile-id', required=True)
    hermes_writeback.set_defaults(func=cmd_hermes_writeback_status)
    hermes_overflow = hermes_sub.add_parser('overflow-pressure', help='Report leak-safe controlled-fixture MEMORY.md/USER.md pressure metrics; no live profile read or mutation.')
    hermes_overflow.add_argument('--profile-id', required=True)
    hermes_overflow.add_argument('--fixture-root', required=True, help='Temporary controlled fixture root containing MEMORY.md and/or USER.md.')
    hermes_overflow.set_defaults(func=cmd_hermes_overflow_pressure)
    hermes_live_status = hermes_sub.add_parser('live-overflow-status', help='Report live Hermes MEMORY.md/USER.md pressure for authorized profile memory roots; no mutation.')
    hermes_live_status.add_argument('--profile-id', action='append')
    hermes_live_status.add_argument('--hermes-home')
    hermes_live_status.set_defaults(func=cmd_hermes_live_overflow_status)
    hermes_live_sweep = hermes_sub.add_parser('live-overflow-sweep', help='Run the bounded automatic overflow coordinator when live_overflow_trim is selected in the profile Mnemoir config.')
    hermes_live_sweep.add_argument('--profile-id', action='append')
    hermes_live_sweep.add_argument('--hermes-home')
    hermes_live_sweep.add_argument('--backup-root')
    hermes_live_sweep.set_defaults(func=cmd_hermes_live_overflow_sweep)
    hermes_live_trim = hermes_sub.add_parser('live-overflow-trim', help='Execute authorized Mnemoir-native live MEMORY.md/USER.md overflow trim/writeback with backup, Mnemoir evidence or pending-evidence spool, atomic write, read-back, and audit receipts.')
    hermes_live_trim.add_argument('--profile-id', action='append')
    hermes_live_trim.add_argument('--hermes-home')
    hermes_live_trim.add_argument('--backup-root')
    hermes_live_trim.add_argument('--authorization-file', required=True, help='Private (0600) external capability JSON.')
    hermes_live_trim.set_defaults(func=cmd_hermes_live_overflow_trim)
    hermes_live_reconcile = hermes_sub.add_parser('live-overflow-reconcile', help='Reconcile one journaled writeback operation using its original private external capability.')
    hermes_live_reconcile.add_argument('--operation-id', required=True)
    hermes_live_reconcile.add_argument('--backup-root', required=True)
    hermes_live_reconcile.add_argument('--authorization-file', required=True)
    hermes_live_reconcile.set_defaults(func=cmd_hermes_live_overflow_reconcile)
    hermes_live_rollback = hermes_sub.add_parser('live-overflow-rollback', help='Execute an externally authorized rollback of one completed writeback operation.')
    hermes_live_rollback.add_argument('--original-operation-id', required=True)
    hermes_live_rollback.add_argument('--backup-root', required=True)
    hermes_live_rollback.add_argument('--authorization-file', required=True)
    hermes_live_rollback.set_defaults(func=cmd_hermes_live_overflow_rollback)
    hermes_live_ingest = hermes_sub.add_parser('live-overflow-ingest-pending', help='Ingest Mnemoir-native private pending-evidence spools into Mnemoir raw_events/evidence/audit and mark spools ingested.')
    hermes_live_ingest.add_argument('--profile-id', action='append')
    hermes_live_ingest.add_argument('--hermes-home')
    hermes_live_ingest.add_argument('--backup-root')
    hermes_live_ingest.add_argument('--limit', type=int)
    hermes_live_ingest.add_argument('--dry-run', action='store_true')
    hermes_live_ingest.add_argument('--keep-pending', action='store_true', help='Leave pending spool files in place after successful DB ingest.')
    hermes_live_ingest.set_defaults(func=cmd_hermes_live_overflow_ingest_pending)
    return parser

def main(argv: list[str] | None=None) -> int:
    parser = build_parser()
    parser.add_argument('--version', action='version', version='%(prog)s 0.2.0-rc.1')
    args = parser.parse_args(argv)
    return args.func(args)
if __name__ == '__main__':
    raise SystemExit(main())
