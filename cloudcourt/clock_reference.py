"""External clock reference observations at a resolver site."""

SCHEMA = '''
CREATE TABLE IF NOT EXISTS clock_references(
    id TEXT PRIMARY KEY, site TEXT, source TEXT, local_at INTEGER,
    offset_ms INTEGER, uncertainty_ms INTEGER, expires INTEGER
);
'''


def observe(db, ref_id, site, source, local_at, offset_ms, uncertainty_ms, expires):
    db.executescript(SCHEMA)
    db.execute('INSERT INTO clock_references VALUES(?,?,?,?,?,?,?)',
               (ref_id, site, source, local_at, offset_ms, uncertainty_ms, expires))
