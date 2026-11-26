"""Provisional RF clearance using the latest sample only."""

from .rf_survey import latest

SCHEMA = '''
CREATE TABLE IF NOT EXISTS rf_clearances(
    id TEXT PRIMARY KEY, site TEXT, frequency_khz INTEGER,
    sample_id TEXT, state TEXT
);
'''


def provisional(db, clearance_id, site, frequency_khz, limit_mv):
    db.executescript(SCHEMA)
    sample = latest(db, site, frequency_khz)
    state = 'clear' if sample and sample[1] <= limit_mv else 'blocked'
    db.execute('INSERT INTO rf_clearances VALUES(?,?,?,?,?)',
               (clearance_id, site, frequency_khz, sample[0] if sample else None, state))
    return state
