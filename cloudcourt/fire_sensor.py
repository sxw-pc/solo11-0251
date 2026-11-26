"""Resolver room detector observations."""

SCHEMA = '''
CREATE TABLE IF NOT EXISTS fire_signals(
    id TEXT PRIMARY KEY, room TEXT, detector TEXT, kind TEXT,
    at INTEGER, state TEXT
);
'''


def report(db, signal_id, room, detector, kind, at, state='alarm'):
    db.executescript(SCHEMA)
    db.execute('INSERT INTO fire_signals VALUES(?,?,?,?,?,?)',
               (signal_id, room, detector, kind, at, state))


def alarm_count(db, room):
    db.executescript(SCHEMA)
    return db.execute('''SELECT COUNT(*) FROM fire_signals
                         WHERE room=? AND state='alarm' ''', (room,)).fetchone()[0]
