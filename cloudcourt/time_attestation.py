"""A provisional timestamp using the most recent reference."""

SCHEMA = '''
CREATE TABLE IF NOT EXISTS time_attestations(
    id TEXT PRIMARY KEY, site TEXT, subject TEXT, reference TEXT,
    claimed_ms INTEGER, state TEXT
);
'''


def provisional(db, attestation_id, site, subject, local_ms):
    db.executescript(SCHEMA)
    ref = db.execute('''SELECT id,offset_ms FROM clock_references
                        WHERE site=? ORDER BY local_at DESC LIMIT 1''',
                     (site,)).fetchone()
    if not ref:
        return None
    claimed = local_ms + ref[1]
    db.execute('INSERT INTO time_attestations VALUES(?,?,?,?,?,?)',
               (attestation_id, site, subject, ref[0], claimed, 'provisional'))
    return claimed
