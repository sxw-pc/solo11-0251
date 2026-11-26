"""A provisional export of tenant policy rows."""

import json

SCHEMA = '''
CREATE TABLE IF NOT EXISTS policy_bundles(
    id TEXT PRIMARY KEY, tenant TEXT, document TEXT, state TEXT
);
'''


def export(db, bundle_id, tenant):
    db.executescript(SCHEMA)
    profiles = [dict(zip(('id','host'), row)) for row in db.execute(
        'SELECT id,host FROM destination_profiles WHERE tenant=?', (tenant,))]
    purposes = [dict(zip(('id','profile','purpose'), row)) for row in db.execute(
        'SELECT id,profile,purpose FROM purpose_contracts WHERE tenant=?', (tenant,))]
    document = json.dumps({'profiles': profiles, 'purposes': purposes}, sort_keys=True)
    db.execute('INSERT INTO policy_bundles VALUES(?,?,?,?)',
               (bundle_id, tenant, document, 'draft'))
    return document
