-- Mnemoir Provenance initial schema
-- Best-in-class local-first agent memory schema for source-grounded, auditable,
-- correctable, benchmarkable Hermes/Council memory.
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

-- -----------------------------------------------------------------------------
-- Schema / migration metadata
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  checksum TEXT NOT NULL CHECK (length(checksum) >= 16),
  applied_at TEXT NOT NULL,
  app_version TEXT,
  success INTEGER NOT NULL DEFAULT 1 CHECK (success IN (0,1)),
  error TEXT
);

INSERT OR IGNORE INTO schema_migrations(version, name, checksum, applied_at, app_version)
VALUES ('0001', 'initial best-in-class local memory schema', '0001-initial-schema-foundation-v1', '1970-01-01T00:00:00Z', 'foundation');

-- -----------------------------------------------------------------------------
-- Core identity, project, and source registry
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS actors (
  actor_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('human','agent','tool','system','organization')),
  display_name TEXT NOT NULL CHECK (length(display_name) > 0),
  handle TEXT,
  profile_name TEXT,
  public_card_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(public_card_json)),
  private_card_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(private_card_json)),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  project_id TEXT PRIMARY KEY,
  name TEXT NOT NULL CHECK (length(name) > 0),
  slug TEXT UNIQUE,
  owner_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','archived','deleted')),
  privacy_class TEXT NOT NULL DEFAULT 'private' CHECK (privacy_class IN ('public','internal','private','sensitive','secret')),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
  source_id TEXT PRIMARY KEY,
  source_type TEXT NOT NULL CHECK (source_type IN ('hermes_state_db','hermes_profile_memory','hermes_markdown_overflow','honcho','session_search','obsidian_wiki','repo_docs','xbrain','council_core','file','api','manual','tool','system')),
  display_name TEXT NOT NULL CHECK (length(display_name) > 0),
  external_ref TEXT,
  profile_id TEXT,
  overflow_kind TEXT CHECK (overflow_kind IS NULL OR overflow_kind IN ('memory_md','user_md','honcho','session','wiki','repo','xbrain')),
  read_authority TEXT NOT NULL DEFAULT 'none' CHECK (read_authority IN ('none','read_only','read_sensitive')),
  write_authority TEXT NOT NULL DEFAULT 'none' CHECK (write_authority IN ('none','propose_only','write_allowed')),
  authority_level TEXT NOT NULL DEFAULT 'secondary' CHECK (authority_level IN ('primary','secondary','derived','untrusted')),
  health TEXT NOT NULL DEFAULT 'unknown' CHECK (health IN ('unknown','healthy','degraded','unavailable','unauthorized','disabled')),
  last_sync_at TEXT,
  freshness_seconds INTEGER CHECK (freshness_seconds IS NULL OR freshness_seconds >= 0),
  failure_reason TEXT,
  provenance_rules_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(provenance_rules_json)),
  privacy_policy_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(privacy_policy_json)),
  created_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
  updated_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z'
);

CREATE TABLE IF NOT EXISTS source_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE CASCADE,
  snapshot_hash TEXT NOT NULL CHECK (length(snapshot_hash) >= 16),
  snapshot_ref TEXT,
  captured_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  UNIQUE(source_id, snapshot_hash)
);

CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE RESTRICT,
  external_ref TEXT,
  parent_session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
  project_id TEXT REFERENCES projects(project_id) ON DELETE SET NULL,
  title TEXT,
  started_at TEXT,
  ended_at TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','closed','archived','deleted')),
  privacy_class TEXT NOT NULL DEFAULT 'private' CHECK (privacy_class IN ('public','internal','private','sensitive','secret')),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
  updated_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
  CHECK (ended_at IS NULL OR started_at IS NULL OR ended_at >= started_at)
);

-- -----------------------------------------------------------------------------
-- Append-first raw event layer
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS raw_events (
  event_id TEXT PRIMARY KEY,
  session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
  source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE RESTRICT,
  snapshot_id TEXT REFERENCES source_snapshots(snapshot_id) ON DELETE SET NULL,
  speaker_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('message','tool_call','tool_result','file_block','memory_block','system_event','import','manual_note','observation','receipt')),
  content TEXT NOT NULL,
  content_hash TEXT NOT NULL CHECK (length(content_hash) >= 16),
  occurred_at TEXT NOT NULL,
  ingested_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
  visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('public','internal','private','sensitive','secret')),
  privacy_class TEXT NOT NULL DEFAULT 'private' CHECK (privacy_class IN ('public','internal','private','sensitive','secret')),
  source_pointer TEXT,
  line_start INTEGER CHECK (line_start IS NULL OR line_start >= 1),
  line_end INTEGER CHECK (line_end IS NULL OR line_end >= line_start),
  byte_start INTEGER CHECK (byte_start IS NULL OR byte_start >= 0),
  byte_end INTEGER CHECK (byte_end IS NULL OR byte_end >= byte_start),
  provenance_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(provenance_json)),
  write_status TEXT NOT NULL DEFAULT 'committed' CHECK (write_status IN ('draft','committed','quarantined','redacted','tombstoned')),
  previous_event_hash TEXT,
  event_hash TEXT,
  correlation_id TEXT,
  causation_id TEXT,
  schema_version TEXT NOT NULL DEFAULT '1',
  UNIQUE(source_id, content_hash, occurred_at)
);

-- -----------------------------------------------------------------------------
-- Normalized evidence / provenance graph
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence_items (
  evidence_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('message','document','url','file','api','observation','memory','manual','tool_result','receipt')),
  source_id TEXT REFERENCES sources(source_id) ON DELETE SET NULL,
  raw_event_id TEXT REFERENCES raw_events(event_id) ON DELETE SET NULL,
  uri TEXT,
  locator_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(locator_json)),
  quote_text TEXT,
  content_hash TEXT CHECK (content_hash IS NULL OR length(content_hash) >= 16),
  trust_score REAL NOT NULL DEFAULT 0.5 CHECK (trust_score >= 0.0 AND trust_score <= 1.0),
  privacy_class TEXT NOT NULL DEFAULT 'private' CHECK (privacy_class IN ('public','internal','private','sensitive','secret')),
  observed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provenance_edges (
  edge_id TEXT PRIMARY KEY,
  from_type TEXT NOT NULL CHECK (from_type IN ('source','session','raw_event','evidence','observation','memory','memory_version','job','audit','benchmark','retrieval_query')),
  from_id TEXT NOT NULL,
  to_type TEXT NOT NULL CHECK (to_type IN ('source','session','raw_event','evidence','observation','memory','memory_version','job','audit','benchmark','retrieval_query')),
  to_id TEXT NOT NULL,
  relation_type TEXT NOT NULL CHECK (relation_type IN ('supports','contradicts','derived_from','quotes','mentions','supersedes','corrects','caused_by','produced','consumed','evaluates','cites')),
  confidence REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0.0 AND confidence <= 1.0),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  UNIQUE(from_type, from_id, to_type, to_id, relation_type)
);

-- -----------------------------------------------------------------------------
-- Observations and extracted claims
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS observations (
  observation_id TEXT PRIMARY KEY,
  subject_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  observer_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  source_event_id TEXT REFERENCES raw_events(event_id) ON DELETE SET NULL,
  claim TEXT NOT NULL,
  predicate TEXT,
  object_text TEXT,
  value_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(value_json)),
  claim_type TEXT NOT NULL CHECK (claim_type IN ('preference','fact','skill','relationship','state','event','constraint','goal','decision','procedure','failure','commitment','open_loop','reflection')),
  polarity INTEGER NOT NULL DEFAULT 1 CHECK (polarity IN (-1,0,1)),
  confidence REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0.0 AND confidence <= 1.0),
  valid_from TEXT,
  valid_until TEXT,
  superseded_by TEXT REFERENCES observations(observation_id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','superseded','retracted','expired','quarantined')),
  privacy_class TEXT NOT NULL DEFAULT 'private' CHECK (privacy_class IN ('public','internal','private','sensitive','secret')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
  CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until >= valid_from)
);

CREATE TABLE IF NOT EXISTS observation_evidence (
  observation_id TEXT NOT NULL REFERENCES observations(observation_id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence_items(evidence_id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('primary','supporting','contradicting','context','audit')),
  weight REAL NOT NULL DEFAULT 1.0 CHECK (weight >= 0.0 AND weight <= 1.0),
  created_at TEXT NOT NULL,
  PRIMARY KEY (observation_id, evidence_id, role)
);

-- -----------------------------------------------------------------------------
-- Memory curation proposals, clusters, stable identities, versions, correction lifecycle
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memory_proposals (
  proposal_id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed','approved','rejected','edited','written','tombstoned','rollback_requested','rolled_back')),
  target_source_id TEXT NOT NULL REFERENCES sources(source_id) ON DELETE RESTRICT,
  memory_id TEXT REFERENCES memories(memory_id) ON DELETE SET NULL,
  title TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL,
  body TEXT NOT NULL,
  memory_type TEXT NOT NULL DEFAULT 'semantic' CHECK (memory_type IN ('semantic','episodic','procedural','preference','profile','project_state','decision','plan','reflection','task','warning','failure','commitment','open_loop')),
  scope TEXT NOT NULL DEFAULT 'global' CHECK (scope IN ('global','actor','project','session','source','council')),
  privacy_class TEXT NOT NULL DEFAULT 'private' CHECK (privacy_class IN ('public','internal','private','sensitive','secret')),
  source_event_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(source_event_ids_json) AND json_type(source_event_ids_json) = 'array'),
  evidence_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(evidence_ids_json) AND json_type(evidence_ids_json) = 'array'),
  operator_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  reviewer_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  review_reason TEXT,
  content_hash TEXT NOT NULL CHECK (length(content_hash) >= 16),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  reviewed_at TEXT,
  written_at TEXT,
  CHECK (json_array_length(source_event_ids_json) > 0 OR json_array_length(evidence_ids_json) > 0)
);

CREATE INDEX IF NOT EXISTS idx_memory_proposals_status ON memory_proposals(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_memory_proposals_memory ON memory_proposals(memory_id, status);

CREATE TABLE IF NOT EXISTS memory_clusters (
  cluster_id TEXT PRIMARY KEY,
  scope TEXT NOT NULL CHECK (scope IN ('global','actor','project','session','source','council')),
  owner_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  project_id TEXT REFERENCES projects(project_id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived','deleted')),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memories (
  memory_id TEXT PRIMARY KEY,
  cluster_id TEXT REFERENCES memory_clusters(cluster_id) ON DELETE SET NULL,
  scope TEXT NOT NULL CHECK (scope IN ('global','actor','project','session','source','council')),
  owner_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  subject_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  project_id TEXT REFERENCES projects(project_id) ON DELETE SET NULL,
  memory_type TEXT NOT NULL CHECK (memory_type IN ('semantic','episodic','procedural','preference','profile','project_state','decision','plan','reflection','task','warning','failure','commitment','open_loop')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('draft','active','stale','contradicted','corrected','superseded','retracted','archived','tombstoned','deleted','quarantined')),
  current_version INTEGER NOT NULL DEFAULT 1 CHECK (current_version >= 1),
  confidence REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0.0 AND confidence <= 1.0),
  salience REAL NOT NULL DEFAULT 0.0 CHECK (salience >= 0.0 AND salience <= 1.0),
  novelty REAL NOT NULL DEFAULT 0.0 CHECK (novelty >= 0.0 AND novelty <= 1.0),
  contradiction_score REAL NOT NULL DEFAULT 0.0 CHECK (contradiction_score >= 0.0 AND contradiction_score <= 1.0),
  stability REAL NOT NULL DEFAULT 0.0 CHECK (stability >= 0.0 AND stability <= 1.0),
  drift_score REAL NOT NULL DEFAULT 0.0 CHECK (drift_score >= 0.0 AND drift_score <= 1.0),
  retention_strength REAL NOT NULL DEFAULT 0.0 CHECK (retention_strength >= 0.0 AND retention_strength <= 1.0),
  retrieval_success_rate REAL NOT NULL DEFAULT 0.0 CHECK (retrieval_success_rate >= 0.0 AND retrieval_success_rate <= 1.0),
  privacy_class TEXT NOT NULL DEFAULT 'private' CHECK (privacy_class IN ('public','internal','private','sensitive','secret')),
  retention_policy_id TEXT,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_recalled_at TEXT,
  recall_count INTEGER NOT NULL DEFAULT 0 CHECK (recall_count >= 0)
);

CREATE TABLE IF NOT EXISTS memory_versions (
  memory_id TEXT NOT NULL REFERENCES memories(memory_id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK (version >= 1),
  title TEXT NOT NULL DEFAULT '',
  summary TEXT NOT NULL,
  body TEXT NOT NULL,
  change_type TEXT NOT NULL CHECK (change_type IN ('create','revise','merge','split','correct','retract','restore','archive','redact')),
  changed_by_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  reason TEXT,
  confidence REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0.0 AND confidence <= 1.0),
  version_hash TEXT NOT NULL CHECK (length(version_hash) >= 16),
  previous_version_hash TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  PRIMARY KEY (memory_id, version)
);

CREATE TABLE IF NOT EXISTS memory_evidence (
  memory_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  evidence_id TEXT NOT NULL REFERENCES evidence_items(evidence_id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('primary','supporting','contradicting','context','audit')),
  weight REAL NOT NULL DEFAULT 1.0 CHECK (weight >= 0.0 AND weight <= 1.0),
  created_at TEXT NOT NULL,
  PRIMARY KEY (memory_id, version, evidence_id, role),
  FOREIGN KEY (memory_id, version) REFERENCES memory_versions(memory_id, version) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS memory_observations (
  memory_id TEXT NOT NULL REFERENCES memories(memory_id) ON DELETE CASCADE,
  observation_id TEXT NOT NULL REFERENCES observations(observation_id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('source','support','contradiction','derived','context')),
  weight REAL NOT NULL DEFAULT 1.0 CHECK (weight >= 0.0 AND weight <= 1.0),
  created_at TEXT NOT NULL,
  PRIMARY KEY (memory_id, observation_id, role)
);

CREATE TABLE IF NOT EXISTS memory_relationships (
  from_memory_id TEXT NOT NULL REFERENCES memories(memory_id) ON DELETE CASCADE,
  to_memory_id TEXT NOT NULL REFERENCES memories(memory_id) ON DELETE CASCADE,
  relationship_type TEXT NOT NULL CHECK (relationship_type IN ('supports','contradicts','supersedes','duplicates','generalizes','specializes','derived_from','related_to')),
  confidence REAL NOT NULL DEFAULT 0.5 CHECK (confidence >= 0.0 AND confidence <= 1.0),
  created_at TEXT NOT NULL,
  PRIMARY KEY (from_memory_id, to_memory_id, relationship_type),
  CHECK (from_memory_id <> to_memory_id)
);

CREATE TABLE IF NOT EXISTS memory_corrections (
  correction_id TEXT PRIMARY KEY,
  memory_id TEXT NOT NULL REFERENCES memories(memory_id) ON DELETE CASCADE,
  from_version INTEGER,
  to_version INTEGER,
  correction_type TEXT NOT NULL CHECK (correction_type IN ('minor','material','contradiction','privacy','deletion','merge','split','confirmation','retraction')),
  status TEXT NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed','applied','rejected','reverted')),
  rationale TEXT NOT NULL,
  proposed_by_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  approved_by_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  evidence_id TEXT REFERENCES evidence_items(evidence_id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  applied_at TEXT,
  FOREIGN KEY (memory_id, from_version) REFERENCES memory_versions(memory_id, version) ON DELETE SET NULL,
  FOREIGN KEY (memory_id, to_version) REFERENCES memory_versions(memory_id, version) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS memory_lifecycle_events (
  lifecycle_id TEXT PRIMARY KEY,
  memory_id TEXT NOT NULL REFERENCES memories(memory_id) ON DELETE CASCADE,
  from_status TEXT,
  to_status TEXT NOT NULL,
  reason TEXT,
  actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  audit_id TEXT,
  occurred_at TEXT NOT NULL
);

-- -----------------------------------------------------------------------------
-- Council durable state
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS council_items (
  item_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('objective','assignment','decision','blocker','evidence','verdict','handoff','commitment','task')),
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_by_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  assigned_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  project_id TEXT REFERENCES projects(project_id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','blocked','review','closed','archived','deleted')),
  priority INTEGER NOT NULL DEFAULT 0,
  due_at TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS council_role_bindings (
  binding_id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(project_id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (length(role) > 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive','blocked','deleted')),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(project_id, actor_id, role)
);

CREATE TABLE IF NOT EXISTS council_objectives (
  objective_id TEXT PRIMARY KEY,
  project_id TEXT REFERENCES projects(project_id) ON DELETE SET NULL,
  title TEXT NOT NULL CHECK (length(title) > 0),
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','blocked','review','closed','archived')),
  priority INTEGER NOT NULL DEFAULT 0,
  created_by_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  owner_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS council_assignments (
  assignment_id TEXT PRIMARY KEY,
  objective_id TEXT NOT NULL REFERENCES council_objectives(objective_id) ON DELETE CASCADE,
  title TEXT NOT NULL CHECK (length(title) > 0),
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','claimed','in_progress','blocked','complete','closed')),
  assigned_actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE RESTRICT,
  created_by_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  due_at TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS council_records (
  record_id TEXT PRIMARY KEY,
  objective_id TEXT NOT NULL REFERENCES council_objectives(objective_id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('blocker','risk','decision','proposal')),
  title TEXT NOT NULL CHECK (length(title) > 0),
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','blocked','resolved','accepted','rejected','closed','archived')),
  created_by_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  severity TEXT CHECK (severity IS NULL OR severity IN ('low','medium','high','critical')),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS council_evidence_packets (
  packet_id TEXT PRIMARY KEY,
  objective_id TEXT NOT NULL REFERENCES council_objectives(objective_id) ON DELETE CASCADE,
  assignment_id TEXT REFERENCES council_assignments(assignment_id) ON DELETE SET NULL,
  title TEXT NOT NULL CHECK (length(title) > 0),
  summary TEXT NOT NULL,
  refs_json TEXT NOT NULL CHECK (json_valid(refs_json) AND json_type(refs_json) = 'array' AND json_array_length(refs_json) > 0),
  created_by_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'attached' CHECK (status IN ('attached','disputed','superseded','retracted')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS council_evidence_refs (
  link_id TEXT PRIMARY KEY,
  packet_id TEXT NOT NULL REFERENCES council_evidence_packets(packet_id) ON DELETE CASCADE,
  ref_type TEXT NOT NULL CHECK (ref_type IN ('evidence','raw_event','memory','retrieval_query','audit','artifact')),
  ref_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'supporting' CHECK (role IN ('primary','supporting','contradicting','context','audit','artifact')),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  UNIQUE(packet_id, ref_type, ref_id, role)
);

CREATE TABLE IF NOT EXISTS council_reviews (
  review_id TEXT PRIMARY KEY,
  objective_id TEXT NOT NULL REFERENCES council_objectives(objective_id) ON DELETE CASCADE,
  assignment_id TEXT REFERENCES council_assignments(assignment_id) ON DELETE SET NULL,
  evidence_packet_id TEXT REFERENCES council_evidence_packets(packet_id) ON DELETE SET NULL,
  reviewer_actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE RESTRICT,
  outcome TEXT NOT NULL CHECK (outcome IN ('approve','revise','reject','veto','blocked','handoff_required','abstain')),
  rationale TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS council_handoffs (
  handoff_id TEXT PRIMARY KEY,
  objective_id TEXT NOT NULL REFERENCES council_objectives(objective_id) ON DELETE CASCADE,
  phase TEXT,
  title TEXT NOT NULL CHECK (length(title) > 0),
  summary TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'ready' CHECK (status IN ('open','ready','blocked','accepted','closed','superseded')),
  from_actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE RESTRICT,
  to_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  evidence_packet_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(evidence_packet_ids_json) AND json_type(evidence_packet_ids_json) = 'array'),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS council_lifecycle_events (
  lifecycle_event_id TEXT PRIMARY KEY,
  objective_id TEXT NOT NULL REFERENCES council_objectives(objective_id) ON DELETE CASCADE,
  assignment_id TEXT REFERENCES council_assignments(assignment_id) ON DELETE SET NULL,
  evidence_packet_id TEXT REFERENCES council_evidence_packets(packet_id) ON DELETE SET NULL,
  review_id TEXT REFERENCES council_reviews(review_id) ON DELETE SET NULL,
  handoff_id TEXT REFERENCES council_handoffs(handoff_id) ON DELETE SET NULL,
  record_id TEXT REFERENCES council_records(record_id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  from_status TEXT,
  to_status TEXT,
  reason TEXT,
  audit_id TEXT REFERENCES audit_events(audit_id) ON DELETE SET NULL,
  occurred_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS council_item_memories (
  item_id TEXT NOT NULL REFERENCES council_items(item_id) ON DELETE CASCADE,
  memory_id TEXT NOT NULL REFERENCES memories(memory_id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'related' CHECK (role IN ('related','source','result','blocker','decision','evidence')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (item_id, memory_id, role)
);

CREATE TABLE IF NOT EXISTS council_item_sessions (
  item_id TEXT NOT NULL REFERENCES council_items(item_id) ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'related' CHECK (role IN ('related','source','handoff','evidence')),
  created_at TEXT NOT NULL,
  PRIMARY KEY (item_id, session_id, role)
);

-- -----------------------------------------------------------------------------
-- Hybrid retrieval, chunks, embeddings, feedback
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS content_chunks (
  chunk_id TEXT PRIMARY KEY,
  owner_type TEXT NOT NULL CHECK (owner_type IN ('raw_event','memory_version','observation','evidence')),
  owner_id TEXT NOT NULL,
  owner_version INTEGER,
  chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
  text TEXT NOT NULL,
  token_count INTEGER CHECK (token_count IS NULL OR token_count >= 0),
  content_hash TEXT NOT NULL CHECK (length(content_hash) >= 16),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  UNIQUE(owner_type, owner_id, owner_version, chunk_index)
);

CREATE TABLE IF NOT EXISTS embedding_models (
  model_id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  model_name TEXT NOT NULL,
  dimension INTEGER NOT NULL CHECK (dimension > 0),
  distance_metric TEXT NOT NULL DEFAULT 'cosine' CHECK (distance_metric IN ('cosine','dot','l2')),
  tokenizer TEXT,
  normalization TEXT,
  local_only INTEGER NOT NULL DEFAULT 1 CHECK (local_only IN (0,1)),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  UNIQUE(provider, model_name, dimension, distance_metric)
);

CREATE TABLE IF NOT EXISTS embeddings (
  embedding_id TEXT PRIMARY KEY,
  target_type TEXT NOT NULL CHECK (target_type IN ('chunk','memory_version','observation','raw_event','evidence')),
  target_id TEXT NOT NULL,
  target_version INTEGER,
  chunk_id TEXT REFERENCES content_chunks(chunk_id) ON DELETE CASCADE,
  model_id TEXT NOT NULL REFERENCES embedding_models(model_id) ON DELETE RESTRICT,
  content_hash TEXT NOT NULL CHECK (length(content_hash) >= 16),
  dims INTEGER NOT NULL CHECK (dims > 0),
  vector_blob BLOB,
  vector_json TEXT CHECK (vector_json IS NULL OR json_valid(vector_json)),
  quantization TEXT NOT NULL DEFAULT 'float32' CHECK (quantization IN ('float32','float16','int8','binary','external')),
  external_index_ref TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(target_type, target_id, target_version, model_id, content_hash)
);

CREATE TABLE IF NOT EXISTS retrieval_queries (
  query_id TEXT PRIMARY KEY,
  actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
  project_id TEXT REFERENCES projects(project_id) ON DELETE SET NULL,
  query_text TEXT NOT NULL,
  query_hash TEXT NOT NULL CHECK (length(query_hash) >= 16),
  purpose TEXT NOT NULL DEFAULT 'answer' CHECK (purpose IN ('answer','context','reflection','benchmark','debug','sync','autonomy')),
  filters_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(filters_json)),
  source_coverage_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(source_coverage_json)),
  started_at TEXT NOT NULL,
  finished_at TEXT,
  latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
  result_count INTEGER NOT NULL DEFAULT 0 CHECK (result_count >= 0),
  status TEXT NOT NULL DEFAULT 'ok' CHECK (status IN ('ok','degraded','failed','abstained'))
);

CREATE TABLE IF NOT EXISTS retrieval_results (
  query_id TEXT NOT NULL REFERENCES retrieval_queries(query_id) ON DELETE CASCADE,
  rank INTEGER NOT NULL CHECK (rank >= 1),
  target_type TEXT NOT NULL CHECK (target_type IN ('raw_event','observation','memory','memory_version','evidence','chunk')),
  target_id TEXT NOT NULL,
  target_version INTEGER,
  channel TEXT NOT NULL CHECK (channel IN ('fts','vector','hybrid','recency','graph','manual','rerank')),
  score_fts REAL,
  score_vector REAL,
  score_recency REAL,
  score_graph REAL,
  score_rerank REAL,
  final_score REAL,
  selected INTEGER NOT NULL DEFAULT 0 CHECK (selected IN (0,1)),
  used_in_answer INTEGER NOT NULL DEFAULT 0 CHECK (used_in_answer IN (0,1)),
  citation_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(citation_json)),
  feedback TEXT CHECK (feedback IS NULL OR feedback IN ('useful','irrelevant','harmful','stale','wrong')),
  PRIMARY KEY (query_id, rank)
);

CREATE TABLE IF NOT EXISTS retrieval_feedback (
  feedback_id TEXT PRIMARY KEY,
  query_id TEXT REFERENCES retrieval_queries(query_id) ON DELETE CASCADE,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  rating INTEGER CHECK (rating IS NULL OR rating BETWEEN -2 AND 2),
  feedback_text TEXT,
  created_at TEXT NOT NULL
);

-- -----------------------------------------------------------------------------
-- compat 15.0.1 learning event and outcome ledger
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS learning_events (
  learning_event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL CHECK (event_type IN (
    'recall.outcome',
    'context_pack.outcome',
    'proposal_review.outcome',
    'memory_correction.outcome',
    'contradiction.outcome',
    'stale_memory.outcome',
    'scoring_feedback.outcome',
    'writeback_policy.outcome',
    'benchmark_regression.outcome',
    'operator_label.outcome'
  )),
  outcome_label TEXT NOT NULL CHECK (outcome_label IN (
    'positive_recall',
    'retrieval_miss',
    'wrong_source_selected',
    'stale_ranked_high',
    'contradiction_not_suppressed',
    'contradiction_correctly_suppressed',
    'useful_memory_reinforced',
    'useful_memory_cooled_too_fast',
    'noisy_signal_consolidated_too_early',
    'context_dropped_needed_citation',
    'context_budget_success',
    'over_trimmed_useful_memory',
    'profile_scope_too_strict',
    'profile_scope_too_loose',
    'proposal_true_positive',
    'proposal_false_positive',
    'unsupported_hot_suppressed',
    'unsupported_hot_leaked',
    'policy_correctly_blocked',
    'policy_false_block',
    'benchmark_regression'
  )),
  failure_class TEXT CHECK (failure_class IS NULL OR failure_class IN (
    'retrieval_miss',
    'wrong_source_selected',
    'stale_ranked_high',
    'contradiction_not_suppressed',
    'useful_memory_cooled_too_fast',
    'noisy_signal_consolidated_too_early',
    'context_dropped_needed_citation',
    'over_trimmed_useful_memory',
    'profile_scope_too_strict',
    'profile_scope_too_loose',
    'proposal_false_positive',
    'unsupported_hot_leaked',
    'policy_false_block',
    'benchmark_regression'
  )),
  severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','watch','warning','critical')),
  profile_id TEXT,
  actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
  query_id TEXT REFERENCES retrieval_queries(query_id) ON DELETE SET NULL,
  memory_id TEXT REFERENCES memories(memory_id) ON DELETE SET NULL,
  proposal_id TEXT REFERENCES memory_proposals(proposal_id) ON DELETE SET NULL,
  source_id TEXT REFERENCES sources(source_id) ON DELETE SET NULL,
  raw_event_id TEXT REFERENCES raw_events(event_id) ON DELETE SET NULL,
  evidence_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(evidence_ids_json) AND json_type(evidence_ids_json) = 'array'),
  related_ids_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(related_ids_json) AND json_type(related_ids_json) = 'object'),
  input_hash TEXT CHECK (input_hash IS NULL OR length(input_hash) >= 16),
  output_hash TEXT CHECK (output_hash IS NULL OR length(output_hash) >= 16),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json) AND json_type(metadata_json) = 'object'),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS learning_failure_clusters (
  cluster_id TEXT PRIMARY KEY,
  failure_class TEXT NOT NULL,
  event_count INTEGER NOT NULL CHECK (event_count >= 0),
  severity_max TEXT NOT NULL CHECK (severity_max IN ('info','watch','warning','critical')),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  sample_event_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(sample_event_ids_json) AND json_type(sample_event_ids_json) = 'array'),
  source_coverage_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(source_coverage_json) AND json_type(source_coverage_json) = 'object'),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','watch','resolved','ignored')),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json) AND json_type(metadata_json) = 'object'),
  updated_at TEXT NOT NULL
);

-- -----------------------------------------------------------------------------
-- compat 15.0.2 offline candidate experiment harness
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS memory_model_versions (
  model_version_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('baseline','candidate')),
  parent_model_version_id TEXT REFERENCES memory_model_versions(model_version_id) ON DELETE SET NULL,
  config_json TEXT NOT NULL CHECK (json_valid(config_json) AND json_type(config_json) = 'object'),
  config_hash TEXT NOT NULL CHECK (length(config_hash) >= 16),
  status TEXT NOT NULL CHECK (status IN ('baseline','candidate','rejected','experiment_only')),
  created_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json) AND json_type(metadata_json) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_memory_model_versions_kind_status ON memory_model_versions(kind, status, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_memory_model_versions_hash_kind_created ON memory_model_versions(kind, config_hash, created_at);

CREATE TABLE IF NOT EXISTS candidate_experiments (
  experiment_id TEXT PRIMARY KEY,
  baseline_model_version_id TEXT NOT NULL REFERENCES memory_model_versions(model_version_id) ON DELETE RESTRICT,
  candidate_model_version_id TEXT NOT NULL REFERENCES memory_model_versions(model_version_id) ON DELETE RESTRICT,
  fixture_suite_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pass','fail','blocked','error')),
  safety_gate_status TEXT NOT NULL CHECK (safety_gate_status IN ('pass','fail','blocked')),
  started_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  metrics_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metrics_json) AND json_type(metrics_json) = 'object'),
  metric_deltas_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metric_deltas_json) AND json_type(metric_deltas_json) = 'object'),
  safety_findings_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(safety_findings_json) AND json_type(safety_findings_json) = 'object'),
  rollback_metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(rollback_metadata_json) AND json_type(rollback_metadata_json) = 'object'),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json) AND json_type(metadata_json) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_candidate_experiments_candidate_status ON candidate_experiments(candidate_model_version_id, status, started_at);
CREATE INDEX IF NOT EXISTS idx_candidate_experiments_baseline ON candidate_experiments(baseline_model_version_id, started_at);

CREATE TABLE IF NOT EXISTS candidate_experiment_cases (
  experiment_case_id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL REFERENCES candidate_experiments(experiment_id) ON DELETE CASCADE,
  case_id TEXT NOT NULL,
  case_type TEXT NOT NULL,
  baseline_result_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(baseline_result_json) AND json_type(baseline_result_json) = 'object'),
  candidate_result_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(candidate_result_json) AND json_type(candidate_result_json) = 'object'),
  metric_deltas_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metric_deltas_json) AND json_type(metric_deltas_json) = 'object'),
  safety_flags_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(safety_flags_json) AND json_type(safety_flags_json) = 'object'),
  status TEXT NOT NULL CHECK (status IN ('pass','fail','blocked','error')),
  created_at TEXT NOT NULL,
  UNIQUE(experiment_id, case_id)
);

CREATE INDEX IF NOT EXISTS idx_candidate_experiment_cases_experiment ON candidate_experiment_cases(experiment_id, case_type, status);

-- -----------------------------------------------------------------------------
-- Policy, privacy, access, redaction, retention
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS privacy_policies (
  policy_id TEXT PRIMARY KEY,
  policy_type TEXT NOT NULL CHECK (policy_type IN ('retention','access','redaction','sharing','deletion','writeback','source_boundary')),
  name TEXT NOT NULL,
  rule_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(rule_json)),
  priority INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS data_subjects (
  subject_id TEXT PRIMARY KEY,
  actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  jurisdiction TEXT,
  consent_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(consent_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_grants (
  grant_id TEXT PRIMARY KEY,
  actor_id TEXT NOT NULL REFERENCES actors(actor_id) ON DELETE CASCADE,
  scope_type TEXT NOT NULL CHECK (scope_type IN ('global','actor','project','session','source','memory','council')),
  scope_id TEXT NOT NULL,
  permission TEXT NOT NULL CHECK (permission IN ('read','write','delete','admin','export','sync','approve')),
  policy_id TEXT REFERENCES privacy_policies(policy_id) ON DELETE SET NULL,
  expires_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(actor_id, scope_type, scope_id, permission)
);

CREATE TABLE IF NOT EXISTS policy_decisions (
  decision_id TEXT PRIMARY KEY,
  policy_id TEXT REFERENCES privacy_policies(policy_id) ON DELETE SET NULL,
  actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  decision TEXT NOT NULL CHECK (decision IN ('allow','deny','require_approval','redact','degrade')),
  reason TEXT,
  request_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(request_json)),
  result_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(result_json)),
  decided_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS redaction_requests (
  request_id TEXT PRIMARY KEY,
  subject_id TEXT REFERENCES data_subjects(subject_id) ON DELETE SET NULL,
  target_type TEXT NOT NULL CHECK (target_type IN ('raw_event','observation','memory','memory_version','evidence','source','session')),
  target_id TEXT NOT NULL,
  request_type TEXT NOT NULL CHECK (request_type IN ('redact','delete','export','restrict','correct')),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','approved','denied','completed','cancelled')),
  reason TEXT,
  requested_by_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  reviewed_by_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS retention_policies (
  retention_policy_id TEXT PRIMARY KEY,
  scope TEXT NOT NULL CHECK (scope IN ('global','actor','project','session','source','council')),
  privacy_class TEXT NOT NULL CHECK (privacy_class IN ('public','internal','private','sensitive','secret')),
  memory_type TEXT,
  ttl_seconds INTEGER CHECK (ttl_seconds IS NULL OR ttl_seconds >= 0),
  decay_rate REAL NOT NULL DEFAULT 0.0 CHECK (decay_rate >= 0.0 AND decay_rate <= 1.0),
  purge_strategy TEXT NOT NULL DEFAULT 'tombstone' CHECK (purge_strategy IN ('retain','archive','tombstone','redact','purge')),
  created_at TEXT NOT NULL
);

-- -----------------------------------------------------------------------------
-- compat 15.0.x self-learning memory evolution records
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS learning_events (
  learning_event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  outcome_label TEXT NOT NULL,
  failure_class TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('info','watch','warning','critical')),
  profile_id TEXT,
  actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  session_id TEXT REFERENCES sessions(session_id) ON DELETE SET NULL,
  query_id TEXT REFERENCES retrieval_queries(query_id) ON DELETE SET NULL,
  memory_id TEXT REFERENCES memories(memory_id) ON DELETE SET NULL,
  proposal_id TEXT,
  source_id TEXT REFERENCES sources(source_id) ON DELETE SET NULL,
  raw_event_id TEXT REFERENCES raw_events(event_id) ON DELETE SET NULL,
  evidence_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(evidence_ids_json) AND json_type(evidence_ids_json) = 'array'),
  related_ids_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(related_ids_json)),
  input_hash TEXT CHECK (input_hash IS NULL OR length(input_hash) >= 16),
  output_hash TEXT CHECK (output_hash IS NULL OR length(output_hash) >= 16),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS learning_failure_clusters (
  cluster_id TEXT PRIMARY KEY,
  failure_class TEXT NOT NULL,
  event_count INTEGER NOT NULL CHECK (event_count >= 0),
  severity_max TEXT NOT NULL CHECK (severity_max IN ('info','watch','warning','critical')),
  first_seen_at TEXT,
  last_seen_at TEXT,
  sample_event_ids_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(sample_event_ids_json) AND json_type(sample_event_ids_json) = 'array'),
  source_coverage_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(source_coverage_json)),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','watch','resolved','blocked')),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_model_versions (
  model_version_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('baseline','candidate')),
  parent_model_version_id TEXT REFERENCES memory_model_versions(model_version_id) ON DELETE SET NULL,
  config_json TEXT NOT NULL CHECK (json_valid(config_json)),
  config_hash TEXT NOT NULL CHECK (length(config_hash) >= 16),
  status TEXT NOT NULL CHECK (status IN ('baseline','candidate','rejected','experiment_only')),
  created_at TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  UNIQUE(kind, parent_model_version_id, config_hash, created_at)
);

CREATE TABLE IF NOT EXISTS candidate_experiments (
  experiment_id TEXT PRIMARY KEY,
  baseline_model_version_id TEXT NOT NULL REFERENCES memory_model_versions(model_version_id) ON DELETE RESTRICT,
  candidate_model_version_id TEXT NOT NULL REFERENCES memory_model_versions(model_version_id) ON DELETE RESTRICT,
  fixture_suite_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pass','fail','blocked','error')),
  safety_gate_status TEXT NOT NULL CHECK (safety_gate_status IN ('pass','fail','blocked')),
  started_at TEXT NOT NULL,
  completed_at TEXT,
  metrics_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metrics_json)),
  metric_deltas_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metric_deltas_json)),
  safety_findings_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(safety_findings_json)),
  rollback_metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(rollback_metadata_json)),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

CREATE TABLE IF NOT EXISTS candidate_experiment_cases (
  experiment_case_id TEXT PRIMARY KEY,
  experiment_id TEXT NOT NULL REFERENCES candidate_experiments(experiment_id) ON DELETE CASCADE,
  case_id TEXT NOT NULL,
  case_type TEXT NOT NULL,
  baseline_result_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(baseline_result_json)),
  candidate_result_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(candidate_result_json)),
  metric_deltas_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metric_deltas_json)),
  safety_flags_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(safety_flags_json)),
  status TEXT NOT NULL CHECK (status IN ('pass','fail','blocked','error')),
  created_at TEXT NOT NULL,
  UNIQUE(experiment_id, case_id)
);

CREATE TABLE IF NOT EXISTS improvement_proposals (
  proposal_id TEXT PRIMARY KEY,
  proposal_type TEXT NOT NULL CHECK (proposal_type IN ('memory_model_config')),
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','experiment_ready','recommended','rejected','approved','promoted','rolled_back','blocked')),
  failure_cluster_id TEXT NOT NULL REFERENCES learning_failure_clusters(cluster_id) ON DELETE RESTRICT,
  baseline_model_version_id TEXT NOT NULL REFERENCES memory_model_versions(model_version_id) ON DELETE RESTRICT,
  candidate_model_version_id TEXT NOT NULL REFERENCES memory_model_versions(model_version_id) ON DELETE RESTRICT,
  experiment_id TEXT REFERENCES candidate_experiments(experiment_id) ON DELETE SET NULL,
  evidence_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(evidence_json)),
  expected_impact_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(expected_impact_json)),
  risk_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(risk_json)),
  safety_requirements_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(safety_requirements_json)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  reviewed_at TEXT,
  reviewer_id TEXT,
  review_decision TEXT CHECK (review_decision IS NULL OR review_decision IN ('approve','reject','block')),
  review_notes_hash TEXT CHECK (review_notes_hash IS NULL OR length(review_notes_hash) >= 16),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  UNIQUE(failure_cluster_id, baseline_model_version_id, candidate_model_version_id)
);

CREATE TABLE IF NOT EXISTS model_promotions (
  promotion_id TEXT PRIMARY KEY,
  proposal_id TEXT NOT NULL REFERENCES improvement_proposals(proposal_id) ON DELETE RESTRICT,
  from_model_version_id TEXT NOT NULL REFERENCES memory_model_versions(model_version_id) ON DELETE RESTRICT,
  to_model_version_id TEXT NOT NULL REFERENCES memory_model_versions(model_version_id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('approved_pending','active_local','rolled_back','blocked')),
  approved_by TEXT,
  approved_at TEXT,
  promoted_at TEXT,
  rolled_back_at TEXT,
  rollback_metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(rollback_metadata_json)),
  audit_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(audit_json)),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

-- -----------------------------------------------------------------------------
-- Audit receipts, jobs, autonomy
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_events (
  audit_id TEXT PRIMARY KEY,
  occurred_at TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  policy_decision_id TEXT REFERENCES policy_decisions(decision_id) ON DELETE SET NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('ok','denied','error','warning','degraded')),
  error TEXT,
  before_hash TEXT,
  after_hash TEXT,
  previous_audit_hash TEXT,
  audit_hash TEXT CHECK (audit_hash IS NULL OR length(audit_hash) >= 16),
  correlation_id TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json))
);

-- compat 17A recoverable, externally-authorized Markdown writeback saga.
CREATE TABLE IF NOT EXISTS writeback_authorizations (
  authorization_id TEXT PRIMARY KEY,
  operation_id TEXT NOT NULL UNIQUE,
  nonce_hash TEXT NOT NULL UNIQUE,
  capability_hash TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  target_path_hash TEXT NOT NULL,
  allowed_root_hash TEXT NOT NULL,
  expected_before_hash TEXT NOT NULL,
  operation_type TEXT NOT NULL CHECK (operation_type IN ('live_overflow_trim','rollback')),
  policy_version TEXT NOT NULL,
  approving_actor TEXT NOT NULL,
  proposal_id TEXT,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS writeback_operations (
  operation_id TEXT PRIMARY KEY,
  authorization_id TEXT NOT NULL REFERENCES writeback_authorizations(authorization_id) ON DELETE RESTRICT,
  profile_id TEXT NOT NULL,
  target_path_hash TEXT NOT NULL,
  allowed_root_hash TEXT NOT NULL,
  target_parent_dev INTEGER,
  target_parent_ino INTEGER,
  expected_before_hash TEXT NOT NULL,
  expected_after_hash TEXT,
  policy_version TEXT NOT NULL,
  operation_type TEXT NOT NULL,
  proposal_id TEXT,
  state TEXT NOT NULL,
  error_code TEXT,
  backup_ref TEXT,
  spool_ref TEXT,
  evidence_state TEXT NOT NULL DEFAULT 'none',
  audit_state TEXT NOT NULL DEFAULT 'none',
  rollback_available INTEGER NOT NULL DEFAULT 0 CHECK (rollback_available IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_writeback_operations_state ON writeback_operations(state, updated_at);

-- compat 17B explicitly invoked bounded worker state. These durable rows are
-- execution receipts/leases; no daemon, scheduler, or autostart is implied.
CREATE TABLE IF NOT EXISTS worker_control (
  worker_name TEXT PRIMARY KEY,
  stop_requested INTEGER NOT NULL DEFAULT 0 CHECK (stop_requested IN (0,1)),
  reason TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS worker_claims (
  claim_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL UNIQUE REFERENCES jobs(job_id) ON DELETE CASCADE,
  worker_id TEXT NOT NULL,
  lease_expires_at TEXT NOT NULL,
  claimed_at TEXT NOT NULL,
  attempt INTEGER NOT NULL CHECK (attempt >= 1)
);
CREATE TABLE IF NOT EXISTS worker_receipts (
  receipt_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  claim_id TEXT NOT NULL,
  worker_id TEXT NOT NULL,
  attempt INTEGER NOT NULL CHECK (attempt >= 1),
  status TEXT NOT NULL CHECK (status IN ('succeeded','failed')),
  output_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(output_json)),
  error TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  UNIQUE(job_id, attempt)
);
CREATE INDEX IF NOT EXISTS idx_worker_claims_lease ON worker_claims(lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_worker_receipts_job ON worker_receipts(job_id, attempt);

CREATE TABLE IF NOT EXISTS jobs (
  job_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  input_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(input_json)),
  input_refs_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(input_refs_json) AND json_type(input_refs_json) = 'array'),
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','succeeded','failed','cancelled','blocked')),
  error TEXT,
  output_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(output_json)),
  output_refs_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(output_refs_json) AND json_type(output_refs_json) = 'array'),
  idempotency_key TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);

CREATE TABLE IF NOT EXISTS job_refs (
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  direction TEXT NOT NULL CHECK (direction IN ('input','output')),
  ref_type TEXT NOT NULL,
  ref_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (job_id, direction, ref_type, ref_id)
);

CREATE TABLE IF NOT EXISTS autonomy_ticks (
  tick_id TEXT PRIMARY KEY,
  job_id TEXT REFERENCES jobs(job_id) ON DELETE SET NULL,
  objective TEXT NOT NULL,
  trigger_type TEXT NOT NULL CHECK (trigger_type IN ('manual','schedule','source_change','policy','benchmark','recovery')),
  actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'planned' CHECK (status IN ('planned','running','succeeded','failed','cancelled','deduped','paused')),
  approval_class TEXT NOT NULL DEFAULT 'none' CHECK (approval_class IN ('none','notify','approval_required','denied')),
  budget_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(budget_json)),
  receipt_audit_id TEXT REFERENCES audit_events(audit_id) ON DELETE SET NULL,
  idempotency_key TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);

-- -----------------------------------------------------------------------------
-- Benchmark and evaluation records
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS benchmark_datasets (
  dataset_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  description TEXT,
  license TEXT,
  source_ref TEXT,
  fixture_hash TEXT CHECK (fixture_hash IS NULL OR length(fixture_hash) >= 16),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS benchmark_cases (
  case_id TEXT PRIMARY KEY,
  dataset_id TEXT NOT NULL REFERENCES benchmark_datasets(dataset_id) ON DELETE CASCADE,
  case_type TEXT NOT NULL CHECK (case_type IN ('recall','fail_closed','writeback','scoring','retrieval','lifecycle','receipt','privacy','portability','regression')),
  query_text TEXT,
  input_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(input_json)),
  expected_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(expected_json)),
  tags_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags_json) AND json_type(tags_json) = 'array'),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS benchmark_runs (
  run_id TEXT PRIMARY KEY,
  dataset_id TEXT REFERENCES benchmark_datasets(dataset_id) ON DELETE SET NULL,
  suite_name TEXT NOT NULL,
  suite_version TEXT NOT NULL,
  app_version TEXT,
  schema_version TEXT,
  model_id TEXT REFERENCES embedding_models(model_id) ON DELETE SET NULL,
  config_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(config_json)),
  seed TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','passed','failed','error','cancelled')),
  notes TEXT
);

CREATE TABLE IF NOT EXISTS benchmark_results (
  run_id TEXT NOT NULL REFERENCES benchmark_runs(run_id) ON DELETE CASCADE,
  case_id TEXT NOT NULL REFERENCES benchmark_cases(case_id) ON DELETE CASCADE,
  query_id TEXT REFERENCES retrieval_queries(query_id) ON DELETE SET NULL,
  passed INTEGER NOT NULL CHECK (passed IN (0,1)),
  score REAL CHECK (score IS NULL OR (score >= 0.0 AND score <= 1.0)),
  latency_ms INTEGER CHECK (latency_ms IS NULL OR latency_ms >= 0),
  metrics_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metrics_json)),
  error TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY (run_id, case_id)
);

-- -----------------------------------------------------------------------------
-- Local-first sync/change tracking
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sync_peers (
  peer_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  endpoint_ref TEXT,
  public_key TEXT,
  trust_level TEXT NOT NULL DEFAULT 'unknown' CHECK (trust_level IN ('trusted','limited','unknown','blocked')),
  metadata_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(metadata_json)),
  created_at TEXT NOT NULL,
  last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS sync_cursors (
  peer_id TEXT NOT NULL REFERENCES sync_peers(peer_id) ON DELETE CASCADE,
  stream_name TEXT NOT NULL,
  cursor_value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (peer_id, stream_name)
);

CREATE TABLE IF NOT EXISTS change_log (
  change_id TEXT PRIMARY KEY,
  table_name TEXT NOT NULL,
  row_pk TEXT NOT NULL,
  operation TEXT NOT NULL CHECK (operation IN ('insert','update','delete','redact','tombstone')),
  actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  before_json TEXT CHECK (before_json IS NULL OR json_valid(before_json)),
  after_json TEXT CHECK (after_json IS NULL OR json_valid(after_json)),
  sync_status TEXT NOT NULL DEFAULT 'pending' CHECK (sync_status IN ('pending','synced','ignored','conflict')),
  changed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_conflicts (
  conflict_id TEXT PRIMARY KEY,
  table_name TEXT NOT NULL,
  row_pk TEXT NOT NULL,
  local_change_id TEXT REFERENCES change_log(change_id) ON DELETE SET NULL,
  remote_ref TEXT,
  conflict_type TEXT NOT NULL CHECK (conflict_type IN ('concurrent_update','delete_update','schema_mismatch','policy_denied','hash_mismatch')),
  resolution_strategy TEXT CHECK (resolution_strategy IS NULL OR resolution_strategy IN ('manual','local_wins','remote_wins','merge','tombstone')),
  resolved_by_actor_id TEXT REFERENCES actors(actor_id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved','ignored')),
  created_at TEXT NOT NULL,
  resolved_at TEXT
);

-- -----------------------------------------------------------------------------
-- FTS5 indexes and triggers
-- -----------------------------------------------------------------------------
CREATE VIRTUAL TABLE IF NOT EXISTS raw_events_fts USING fts5(
  content,
  event_id UNINDEXED,
  source_id UNINDEXED,
  tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS raw_events_ai AFTER INSERT ON raw_events BEGIN
  INSERT INTO raw_events_fts(rowid, content, event_id, source_id)
  VALUES (new.rowid, new.content, new.event_id, new.source_id);
END;

CREATE TRIGGER IF NOT EXISTS raw_events_au AFTER UPDATE OF content, event_id, source_id ON raw_events BEGIN
  DELETE FROM raw_events_fts WHERE rowid = old.rowid;
  INSERT INTO raw_events_fts(rowid, content, event_id, source_id)
  VALUES (new.rowid, new.content, new.event_id, new.source_id);
END;

CREATE TRIGGER IF NOT EXISTS raw_events_ad AFTER DELETE ON raw_events BEGIN
  DELETE FROM raw_events_fts WHERE rowid = old.rowid;
END;

CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
  title,
  summary,
  body,
  memory_id UNINDEXED,
  version UNINDEXED,
  scope UNINDEXED,
  privacy_class UNINDEXED,
  tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS memory_versions_ai AFTER INSERT ON memory_versions BEGIN
  INSERT INTO memories_fts(rowid, title, summary, body, memory_id, version, scope, privacy_class)
  SELECT new.rowid, new.title, new.summary, new.body, m.memory_id, new.version, m.scope, m.privacy_class
  FROM memories m
  WHERE m.memory_id = new.memory_id
    AND m.current_version = new.version
    AND m.status NOT IN ('deleted','retracted','tombstoned','quarantined');
END;

CREATE TRIGGER IF NOT EXISTS memory_versions_au AFTER UPDATE ON memory_versions BEGIN
  DELETE FROM memories_fts WHERE rowid = old.rowid;
  INSERT INTO memories_fts(rowid, title, summary, body, memory_id, version, scope, privacy_class)
  SELECT new.rowid, new.title, new.summary, new.body, m.memory_id, new.version, m.scope, m.privacy_class
  FROM memories m
  WHERE m.memory_id = new.memory_id
    AND m.current_version = new.version
    AND m.status NOT IN ('deleted','retracted','tombstoned','quarantined');
END;

CREATE TRIGGER IF NOT EXISTS memory_versions_ad AFTER DELETE ON memory_versions BEGIN
  DELETE FROM memories_fts WHERE rowid = old.rowid;
END;

CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE OF current_version, status, scope, privacy_class ON memories BEGIN
  DELETE FROM memories_fts WHERE memory_id = old.memory_id;
  INSERT INTO memories_fts(rowid, title, summary, body, memory_id, version, scope, privacy_class)
  SELECT mv.rowid, mv.title, mv.summary, mv.body, new.memory_id, mv.version, new.scope, new.privacy_class
  FROM memory_versions mv
  WHERE mv.memory_id = new.memory_id
    AND mv.version = new.current_version
    AND new.status NOT IN ('deleted','retracted','tombstoned','quarantined');
END;

-- -----------------------------------------------------------------------------
-- Indexes for hot paths, FKs, retrieval, audit, and benchmark reporting
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_actor_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS ux_actors_kind_profile ON actors(kind, profile_name) WHERE profile_name IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_sources_type_external_ref ON sources(source_type, external_ref) WHERE external_ref IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_sessions_source_external_ref ON sessions(source_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_jobs_kind_idempotency ON jobs(kind, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_autonomy_idempotency ON autonomy_ticks(idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sources_type_health ON sources(source_type, health);
CREATE INDEX IF NOT EXISTS idx_sources_profile_overflow ON sources(profile_id, overflow_kind);
CREATE INDEX IF NOT EXISTS idx_sessions_source_time ON sessions(source_id, started_at);
CREATE INDEX IF NOT EXISTS idx_sessions_parent ON sessions(parent_session_id);
CREATE INDEX IF NOT EXISTS idx_raw_events_session_time ON raw_events(session_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_raw_events_source_time ON raw_events(source_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_raw_events_hash ON raw_events(content_hash);
CREATE INDEX IF NOT EXISTS idx_raw_events_speaker ON raw_events(speaker_actor_id);
CREATE INDEX IF NOT EXISTS idx_evidence_source_time ON evidence_items(source_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_evidence_raw_event ON evidence_items(raw_event_id);
CREATE INDEX IF NOT EXISTS idx_provenance_to ON provenance_edges(to_type, to_id, relation_type);
CREATE INDEX IF NOT EXISTS idx_provenance_from ON provenance_edges(from_type, from_id, relation_type);
CREATE INDEX IF NOT EXISTS idx_observations_subject_type ON observations(subject_actor_id, claim_type, status);
CREATE INDEX IF NOT EXISTS idx_observations_source_event ON observations(source_event_id);
CREATE INDEX IF NOT EXISTS idx_observations_superseded_by ON observations(superseded_by);
CREATE INDEX IF NOT EXISTS idx_observation_evidence_evidence ON observation_evidence(evidence_id);
CREATE INDEX IF NOT EXISTS idx_memory_clusters_scope ON memory_clusters(scope, owner_actor_id, status);
CREATE INDEX IF NOT EXISTS idx_memories_scope_status ON memories(scope, owner_actor_id, status, updated_at);
CREATE INDEX IF NOT EXISTS idx_memories_subject_status ON memories(subject_actor_id, status);
CREATE INDEX IF NOT EXISTS idx_memories_project_status ON memories(project_id, status);
CREATE INDEX IF NOT EXISTS idx_memories_type_salience ON memories(memory_type, salience DESC, confidence DESC);
CREATE INDEX IF NOT EXISTS idx_memory_versions_created ON memory_versions(memory_id, created_at);
CREATE INDEX IF NOT EXISTS idx_memory_evidence_evidence ON memory_evidence(evidence_id);
CREATE INDEX IF NOT EXISTS idx_memory_relationships_to ON memory_relationships(to_memory_id, relationship_type);
CREATE INDEX IF NOT EXISTS idx_memory_corrections_memory ON memory_corrections(memory_id, status);
CREATE INDEX IF NOT EXISTS idx_lifecycle_memory_time ON memory_lifecycle_events(memory_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_council_status_priority_due ON council_items(status, priority DESC, due_at);
CREATE INDEX IF NOT EXISTS idx_council_assigned_status ON council_items(assigned_actor_id, status);
CREATE INDEX IF NOT EXISTS idx_council_roles_actor ON council_role_bindings(actor_id, status);
CREATE INDEX IF NOT EXISTS idx_council_objectives_status ON council_objectives(project_id, status, priority DESC, updated_at);
CREATE INDEX IF NOT EXISTS idx_council_assignments_objective ON council_assignments(objective_id, status, assigned_actor_id);
CREATE INDEX IF NOT EXISTS idx_council_records_objective ON council_records(objective_id, kind, status);
CREATE INDEX IF NOT EXISTS idx_council_evidence_objective ON council_evidence_packets(objective_id, assignment_id, status);
CREATE INDEX IF NOT EXISTS idx_council_evidence_refs_ref ON council_evidence_refs(ref_type, ref_id);
CREATE INDEX IF NOT EXISTS idx_council_reviews_objective ON council_reviews(objective_id, outcome, reviewer_actor_id);
CREATE INDEX IF NOT EXISTS idx_council_handoffs_search ON council_handoffs(objective_id, phase, status, from_actor_id, to_actor_id);
CREATE INDEX IF NOT EXISTS idx_council_lifecycle_objective ON council_lifecycle_events(objective_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_chunks_owner ON content_chunks(owner_type, owner_id, owner_version, chunk_index);
CREATE INDEX IF NOT EXISTS idx_embeddings_target ON embeddings(target_type, target_id, target_version);
CREATE INDEX IF NOT EXISTS idx_retrieval_session_time ON retrieval_queries(session_id, started_at);
CREATE INDEX IF NOT EXISTS idx_retrieval_results_target ON retrieval_results(target_type, target_id, target_version);
CREATE INDEX IF NOT EXISTS idx_learning_events_type_time ON learning_events(event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_learning_events_outcome ON learning_events(outcome_label, failure_class, severity);
CREATE INDEX IF NOT EXISTS idx_learning_events_links ON learning_events(query_id, memory_id, proposal_id, source_id);
CREATE INDEX IF NOT EXISTS idx_learning_clusters_failure ON learning_failure_clusters(failure_class, status, event_count);
CREATE INDEX IF NOT EXISTS idx_memory_model_versions_kind ON memory_model_versions(kind, status, created_at);
CREATE INDEX IF NOT EXISTS idx_candidate_experiments_models ON candidate_experiments(baseline_model_version_id, candidate_model_version_id, status);
CREATE INDEX IF NOT EXISTS idx_candidate_experiment_cases_experiment ON candidate_experiment_cases(experiment_id, status);
CREATE INDEX IF NOT EXISTS idx_improvement_proposals_status ON improvement_proposals(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_improvement_proposals_cluster ON improvement_proposals(failure_cluster_id, status);
CREATE INDEX IF NOT EXISTS idx_model_promotions_status ON model_promotions(status, promoted_at);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_target ON policy_decisions(target_type, target_id, decided_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_target ON audit_events(target_type, target_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor_time ON audit_events(actor_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_jobs_status_priority ON jobs(status, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS idx_autonomy_status_created ON autonomy_ticks(status, created_at);
CREATE INDEX IF NOT EXISTS idx_benchmark_cases_dataset_type ON benchmark_cases(dataset_id, case_type);
CREATE INDEX IF NOT EXISTS idx_benchmark_results_case ON benchmark_results(case_id, passed);
CREATE INDEX IF NOT EXISTS idx_change_sync ON change_log(sync_status, changed_at);
CREATE INDEX IF NOT EXISTS idx_sync_conflicts_status ON sync_conflicts(status, created_at);
