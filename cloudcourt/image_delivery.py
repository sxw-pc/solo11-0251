"""Provisional acceptance of a resolver image by advertised digest."""

SCHEMA = '''
CREATE TABLE IF NOT EXISTS image_deliveries(
    id TEXT PRIMARY KEY, build_id TEXT, customer TEXT,
    accepted_digest TEXT, state TEXT
);
'''


def provisional(db, delivery_id, build_id, customer, offered_digest):
    db.executescript(SCHEMA)
    build = db.execute('SELECT advertised_digest FROM image_builds WHERE id=?',
                       (build_id,)).fetchone()
    state = 'accepted' if build and build[0] == offered_digest else 'rejected'
    db.execute('INSERT INTO image_deliveries VALUES(?,?,?,?,?)',
               (delivery_id, build_id, customer, offered_digest, state))
    return state
