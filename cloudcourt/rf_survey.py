"""Resolver-site radio-frequency survey readings.

A reading is only useful as evidence when it is bound to the instrument's
calibration state, the antenna orientation, the measured band, the physical
measurement point, the time and the equipment load at that time.  The schema
therefore stores all of those fields with every sample.

``calibrated_until`` is the epoch at which the instrument calibration expires.
A sample taken after that instant is recorded but is not admissible evidence.
``config`` identifies the measured equipment configuration; samples taken under
another configuration never qualify a later one.
"""

SCHEMA = '''
CREATE TABLE IF NOT EXISTS rf_samples(
    id TEXT PRIMARY KEY, site TEXT, frequency_khz INTEGER,
    at INTEGER, field_mv INTEGER, instrument TEXT,
    bandwidth_khz INTEGER, calibrated_until INTEGER,
    antenna TEXT, point TEXT, load_pct INTEGER, config TEXT
);
'''


def ensure(db):
    """Create the table without ``executescript`` (safe inside a transaction)."""
    for statement in SCHEMA.split(';'):
        if statement.strip():
            db.execute(statement)


def record(db, sample_id, site, frequency_khz, at, field_mv, instrument,
           bandwidth_khz=0, calibrated_until=None, antenna=None, point=None,
           load_pct=0, config=None):
    """Record a survey sample together with its measurement provenance."""
    ensure(db)
    db.execute(
        'INSERT INTO rf_samples VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (sample_id, site, frequency_khz, at, field_mv, instrument,
         bandwidth_khz, calibrated_until, antenna, point, load_pct, config))


def get(db, sample_id):
    ensure(db)
    row = db.execute('SELECT * FROM rf_samples WHERE id=?', (sample_id,)).fetchone()
    return dict(row) if row else None


def for_config(db, site, config):
    """All samples for one measured configuration, newest first."""
    ensure(db)
    return [dict(row) for row in db.execute(
        '''SELECT * FROM rf_samples
           WHERE site=? AND config IS ? ORDER BY at DESC, rowid DESC''',
        (site, config))]


def latest(db, site, frequency_khz):
    """Latest raw sample (legacy helper; not evidence for a clearance)."""
    ensure(db)
    return db.execute('''SELECT id,field_mv FROM rf_samples
                         WHERE site=? AND frequency_khz=?
                         ORDER BY at DESC, rowid DESC LIMIT 1''',
                      (site, frequency_khz)).fetchone()
