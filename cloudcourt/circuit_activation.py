"""A provisional diverse-circuit declaration by route ID only."""

SCHEMA = '''
CREATE TABLE IF NOT EXISTS circuit_activations(
    id TEXT PRIMARY KEY, tenant TEXT, first_route TEXT,
    second_route TEXT, state TEXT
);
'''


def provisional(db, activation_id, tenant, first_route, second_route):
    db.executescript(SCHEMA)
    a = db.execute('SELECT id FROM fiber_routes WHERE id=?', (first_route,)).fetchone()
    b = db.execute('SELECT id FROM fiber_routes WHERE id=?', (second_route,)).fetchone()
    state = 'diverse' if a and b and first_route != second_route else 'unavailable'
    db.execute('INSERT INTO circuit_activations VALUES(?,?,?,?,?)',
               (activation_id, tenant, first_route, second_route, state))
    return state
