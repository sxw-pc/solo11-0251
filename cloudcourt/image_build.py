"""Provisional resolver image build record."""

import hashlib

SCHEMA = '''
CREATE TABLE IF NOT EXISTS image_builds(
    id TEXT PRIMARY KEY, source_digest TEXT, compiler TEXT,
    recipe TEXT, advertised_digest TEXT, state TEXT
);
'''


def record(db, build_id, source_bytes, compiler, recipe):
    db.executescript(SCHEMA)
    digest = hashlib.sha256(source_bytes).hexdigest()
    db.execute('INSERT INTO image_builds VALUES(?,?,?,?,?,?)',
               (build_id, digest, compiler, recipe, digest, 'built'))
    return digest
