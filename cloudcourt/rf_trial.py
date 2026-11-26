"""Controlled interventions and neighbour reception outcomes.

A trial records whether two devices were running and what the neighbour's
receiver actually did.  It does not, on its own, name a source.  The legacy
``provisional_cause`` helper demonstrates the hazard this module replaces: it
reads only the most recent trial and reports whichever device was running then.
"""

SCHEMA = '''
CREATE TABLE IF NOT EXISTS rf_trials(
    id TEXT PRIMARY KEY, site TEXT, psu_on INTEGER, carrier_on INTEGER,
    load_pct INTEGER, neighbor_errors INTEGER, at INTEGER,
    receiver TEXT, config TEXT, baseline INTEGER, experiment TEXT
);
'''


def ensure(db):
    for statement in SCHEMA.split(';'):
        if statement.strip():
            db.execute(statement)


def observe(db, trial_id, site, psu_on, carrier_on, load_pct, neighbor_errors,
            at, receiver=None, config=None, baseline=0, experiment=None):
    ensure(db)
    db.execute('INSERT INTO rf_trials VALUES(?,?,?,?,?,?,?,?,?,?,?)',
               (trial_id, site, int(psu_on), int(carrier_on), load_pct,
                neighbor_errors, at, receiver, config, baseline, experiment))


def trials(db, site, config=None):
    ensure(db)
    return [dict(row) for row in db.execute(
        '''SELECT * FROM rf_trials WHERE site=? AND config IS ?
           ORDER BY at, rowid''', (site, config))]


def provisional_cause(db, site):
    """Legacy shortcut: attribute to whichever device the last trial left on."""
    ensure(db)
    row = db.execute('''SELECT psu_on,carrier_on,neighbor_errors FROM rf_trials
                        WHERE site=? ORDER BY at DESC LIMIT 1''', (site,)).fetchone()
    if not row:
        return 'unknown'
    if row[2] == 0:
        return 'clear'
    return 'psu' if row[0] else 'carrier'
