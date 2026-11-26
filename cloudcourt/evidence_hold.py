"""Capture a provisional legal hold on a connection record."""
from .store import tx


def hold(db,hold_id,flow_id,case_id):
    with tx(db):
        db.execute('CREATE TABLE IF NOT EXISTS evidence_holds(id TEXT PRIMARY KEY,flow TEXT,case_id TEXT,state TEXT)')
        old=db.execute('SELECT flow,case_id FROM evidence_holds WHERE id=?',(hold_id,)).fetchone()
        if old:return {'decision':'reused' if tuple(old)==(flow_id,case_id) else 'conflict'}
        if not db.execute('SELECT id FROM flow_attempts WHERE id=?',(flow_id,)).fetchone():return {'decision':'unavailable'}
        db.execute('INSERT INTO evidence_holds VALUES (?,?,?,?)',(hold_id,flow_id,case_id,'active'))
        return {'decision':'held'}
