"""Resolver site radio-frequency survey readings."""

SCHEMA = '''
CREATE TABLE IF NOT EXISTS rf_samples(
    id TEXT PRIMARY KEY, site TEXT, frequency_khz INTEGER,
    at INTEGER, field_mv INTEGER, instrument TEXT
);
'''


def record(db, sample_id, site, frequency_khz, at, field_mv, instrument):
    db.executescript(SCHEMA)
    db.execute('INSERT INTO rf_samples VALUES(?,?,?,?,?,?)',
               (sample_id, site, frequency_khz, at, field_mv, instrument))


def latest(db, site, frequency_khz):
    db.executescript(SCHEMA)
    return db.execute('''SELECT id,field_mv FROM rf_samples
                         WHERE site=? AND frequency_khz=?
                         ORDER BY at DESC LIMIT 1''', (site, frequency_khz)).fetchone()
