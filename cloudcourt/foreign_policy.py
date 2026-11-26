"""An isolated target's host-only policy evaluation."""

import json


def allows(db, import_id, host, ip, purpose, resolver_generation):
    row = db.execute('''SELECT b.document FROM foreign_imports i
                        JOIN policy_bundles b ON b.id=i.bundle
                        WHERE i.id=? AND i.state='provisional' ''',
                     (import_id,)).fetchone()
    if not row:
        return False
    document = json.loads(row[0])
    return host in {p['host'] for p in document['profiles']}
