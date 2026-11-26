"""Received optical routes used by resolver sites."""

SCHEMA = '''
CREATE TABLE IF NOT EXISTS fiber_routes(
    id TEXT PRIMARY KEY, supplier TEXT, duct TEXT, splice_box TEXT,
    capacity INTEGER, label TEXT
);
'''


def receive(db, route_id, supplier, duct, splice_box, capacity, label):
    db.executescript(SCHEMA)
    db.execute('INSERT INTO fiber_routes VALUES(?,?,?,?,?,?)',
               (route_id, supplier, duct, splice_box, capacity, label))
