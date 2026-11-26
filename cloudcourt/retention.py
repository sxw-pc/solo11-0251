"""Draft a purge list for settled connections outside a legal hold."""
from .store import tx


def provisional_purge(db,plan_id):
    with tx(db):
        db.execute('CREATE TABLE IF NOT EXISTS evidence_holds(id TEXT PRIMARY KEY,flow TEXT,case_id TEXT,state TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS purge_plans(id TEXT PRIMARY KEY,flows TEXT)')
        old=db.execute('SELECT flows FROM purge_plans WHERE id=?',(plan_id,)).fetchone()
        if old:return {'decision':'reused','flows':old['flows'].split(',') if old['flows'] else []}
        ids=[r[0] for r in db.execute("SELECT id FROM flow_attempts f WHERE status='settled' AND NOT EXISTS (SELECT 1 FROM evidence_holds h WHERE h.flow=f.id AND h.state='active') ORDER BY id")]
        db.execute('INSERT INTO purge_plans VALUES (?,?)',(plan_id,','.join(ids)))
        return {'decision':'planned','flows':ids}
