"""Capture an independent resolver poisoning research submission."""
from .store import tx


def submit(db,report_id,finder,zone,proof_digest,impact):
    with tx(db):
        db.execute('CREATE TABLE IF NOT EXISTS dns_research(id TEXT PRIMARY KEY,finder TEXT,zone TEXT,proof_digest TEXT,impact INTEGER)')
        old=db.execute('SELECT finder,zone,proof_digest,impact FROM dns_research WHERE id=?',(report_id,)).fetchone()
        if old:return {'decision':'reused' if tuple(old)==(finder,zone,proof_digest,impact) else 'conflict'}
        if not finder or not zone or not proof_digest or impact<0:return {'decision':'invalid'}
        db.execute('INSERT INTO dns_research VALUES (?,?,?,?,?)',(report_id,finder,zone,proof_digest,impact))
        return {'decision':'submitted'}
