"""Blocked trims preserve bytes; reviewed block boundaries permit safe trim."""
import pytest
from mnemoir_provenance.db import connect, initialize_database
from mnemoir_provenance.live_overflow import run_live_overflow_coordinator


@pytest.mark.parametrize('text', [
    'x' * 2008,
    '  ' + 'x' * 2008 + '\n\n',
    'credential ' + 'x' * 1200 + '\n\n' + 'secret ' + 'y' * 900,
])
def test_no_removed_blocks_means_no_formatting_write(tmp_path, text):
    home = tmp_path / 'hermes'
    root = home / 'memories'
    root.mkdir(parents=True)
    path = root / 'MEMORY.md'
    path.write_text(text)
    (root / 'USER.md').write_text('small\n')
    with connect(tmp_path / 'test.sqlite') as conn:
        initialize_database(conn)
        first = run_live_overflow_coordinator(conn, profile_ids=('default',), hermes_home=home)
        row = first['rows'][0]
        assert row['state'] == 'blocked_target_unreachable'
        assert first['mutated_file_count'] == 0
        assert path.read_text() == text
        record = conn.execute('SELECT backup_ref, spool_ref FROM writeback_operations').fetchone()
        assert tuple(record) == (None, None)
        assert conn.execute('SELECT COUNT(*) FROM raw_events').fetchone()[0] == 0
        again = run_live_overflow_coordinator(conn, profile_ids=('default',), hermes_home=home)
        assert again['rows'][0]['idempotent_replay'] is True
        assert again['mutated_file_count'] == 0
        assert path.read_text() == text


def test_reviewed_split_preserves_removed_evidence_and_reaches_target(tmp_path):
    home = tmp_path / 'hermes'
    root = home / 'memories'
    root.mkdir(parents=True)
    path = root / 'MEMORY.md'
    blocks = ['Earlier topic: ' + 'a' * 1000, 'Current topic: ' + 'b' * 1000]
    path.write_text(' '.join(blocks))
    (root / 'USER.md').write_text('small\n')
    with connect(tmp_path / 'test.sqlite') as conn:
        initialize_database(conn)
        blocked = run_live_overflow_coordinator(conn, profile_ids=('default',), hermes_home=home)
        assert blocked['rows'][0]['state'] == 'blocked_target_unreachable'
        # Simulate explicitly reviewed, lossless topic-boundary normalization.
        path.write_text('\n§\n'.join(blocks) + '\n')
        result = run_live_overflow_coordinator(conn, profile_ids=('default',), hermes_home=home)
        assert result['status'] == 'succeeded'
        assert result['mutated_file_count'] == 1
        assert path.read_text() == blocks[1] + '\n'
        assert len(path.read_text()) <= 1100
        evidence = conn.execute('SELECT r.content, e.quote_text FROM raw_events r JOIN evidence_items e ON e.raw_event_id=r.event_id').fetchall()
        assert [tuple(r) for r in evidence] == [(blocks[0], blocks[0])]
        again = run_live_overflow_coordinator(conn, profile_ids=('default',), hermes_home=home)
        assert again['status'] == 'succeeded'
        assert again['mutated_file_count'] == 0
