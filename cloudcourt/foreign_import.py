"""A provisional importer acknowledgment by row count."""

import json

SCHEMA = '''
CREATE TABLE IF NOT EXISTS foreign_imports(
    id TEXT PRIMARY KEY, bundle TEXT, platform TEXT, rows INTEGER,
    state TEXT
);
'''


def provisional(db, import_id, bundle_id, platform):
    db.executescript(SCHEMA)
    row = db.execute('SELECT document FROM policy_bundles WHERE id=?',
                     (bundle_id,)).fetchone()
    if not row:
        return 0
    document = json.loads(row[0])
    count = len(document['profiles']) + len(document['purposes'])
    db.execute('INSERT INTO foreign_imports VALUES(?,?,?,?,?)',
               (import_id, bundle_id, platform, count, 'provisional'))
    return count
