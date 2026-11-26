"""Temporary pre-discharge indication, without physical actuation."""

from .fire_sensor import alarm_count

SCHEMA = '''
CREATE TABLE IF NOT EXISTS suppression_intents(
    id TEXT PRIMARY KEY, room TEXT, indication TEXT
);
'''


def indicate(db, intent_id, room):
    db.executescript(SCHEMA)
    indication = 'ready' if alarm_count(db, room) >= 2 else 'watch'
    db.execute('INSERT INTO suppression_intents VALUES(?,?,?)',
               (intent_id, room, indication))
    return indication
