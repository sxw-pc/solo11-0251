"""Controlled interventions and neighbor reception outcomes."""

SCHEMA = '''
CREATE TABLE IF NOT EXISTS rf_trials(
    id TEXT PRIMARY KEY, site TEXT, psu_on INTEGER, carrier_on INTEGER,
    load_pct INTEGER, neighbor_errors INTEGER, at INTEGER
);
'''


def observe(db, trial_id, site, psu_on, carrier_on, load_pct, neighbor_errors, at):
    db.executescript(SCHEMA)
    db.execute('INSERT INTO rf_trials VALUES(?,?,?,?,?,?,?)',
               (trial_id, site, int(psu_on), int(carrier_on), load_pct,
                neighbor_errors, at))


def provisional_cause(db, site):
    db.executescript(SCHEMA)
    row = db.execute('''SELECT psu_on,carrier_on,neighbor_errors FROM rf_trials
                        WHERE site=? ORDER BY at DESC LIMIT 1''', (site,)).fetchone()
    if not row:
        return 'unknown'
    if row[2] == 0:
        return 'clear'
    return 'psu' if row[0] else 'carrier'
