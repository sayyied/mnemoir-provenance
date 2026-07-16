from __future__ import annotations

from pathlib import Path

import pytest

from mnemoir_provenance.db import connect, initialize_database, json_dumps, now_utc, sha256_text


@pytest.fixture
def seeded_db(tmp_path: Path):
    db_path = tmp_path / "mnemoir.sqlite"
    with connect(db_path) as conn:
        initialize_database(conn)
        now = now_utc()
        content = "Synthetic evidence says the demo project uses source-grounded memory."
        content_hash = sha256_text(content)
        conn.execute("INSERT INTO sources(source_id,source_type,display_name,external_ref,read_authority,write_authority,authority_level,health,provenance_rules_json,privacy_policy_json,created_at,updated_at) VALUES('demo_source','manual','Synthetic demo source','fixture://demo','read_only','none','primary','healthy',?,?,?,?)", (json_dumps({"synthetic": True}), json_dumps({"privacy": "internal"}), now, now))
        conn.execute("INSERT INTO raw_events(event_id,source_id,event_type,content,content_hash,occurred_at,ingested_at,visibility,privacy_class,source_pointer,provenance_json) VALUES('demo_event','demo_source','manual_note',?,?,?,?, 'internal','internal','fixture://demo#event',?)", (content, content_hash, now, now, json_dumps({"synthetic": True})))
        conn.execute("INSERT INTO evidence_items(evidence_id,kind,source_id,raw_event_id,uri,quote_text,content_hash,trust_score,privacy_class,observed_at,created_at) VALUES('demo_evidence','manual','demo_source','demo_event','fixture://demo#event',?,?,1.0,'internal',?,?)", (content, content_hash, now, now))
        conn.commit()
    return db_path
