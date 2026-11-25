from .store import act,one
SCHEMA='''
CREATE TABLE IF NOT EXISTS purpose_contracts(id TEXT PRIMARY KEY,tenant TEXT,profile TEXT,purpose TEXT,generation INTEGER,state TEXT);
CREATE TABLE IF NOT EXISTS quota_windows(id TEXT PRIMARY KEY,tenant TEXT,capacity INTEGER,used INTEGER,start INTEGER,expires INTEGER);
CREATE TABLE IF NOT EXISTS egress_grants(id TEXT PRIMARY KEY,contract TEXT,window TEXT,holder TEXT,limit_bytes INTEGER,used INTEGER,generation INTEGER,state TEXT);
'''

def handle(db,x):
    op=x['op']
    if op=='purpose':
        p=one(db,'SELECT * FROM destination_profiles WHERE id=?',(x['profile'],))
        if not p or p['tenant']!=x['tenant'] or p['state']!='active':return {'decision':'profile_unavailable'}
        db.execute('INSERT INTO purpose_contracts VALUES(?,?,?,?,?,?)',(x['id'],x['tenant'],x['profile'],x['purpose'],1,'active'))
        return {'decision':'purpose_approved'}
    if op=='quota':
        if x['capacity']<=0 or x['expires']<=x['start']:return {'decision':'invalid_window'}
        db.execute('INSERT INTO quota_windows VALUES(?,?,?,?,?,?)',(x['id'],x['tenant'],x['capacity'],0,x['start'],x['expires']))
        return {'decision':'window_open'}
    if op=='grant':
        c=one(db,'SELECT * FROM purpose_contracts WHERE id=?',(x['contract'],))
        w=one(db,'SELECT * FROM quota_windows WHERE id=?',(x['window'],))
        p=one(db,'SELECT * FROM destination_profiles WHERE id=?',(c['profile'],)) if c else None
        if not c or c['state']!='active' or not p or p['state']!='active' or not w or w['tenant']!=c['tenant'] or not w['start']<=x['at']<w['expires']:
            return {'decision':'grant_unavailable'}
        observation=one(db,"SELECT * FROM dns_observations WHERE profile=? AND state='accepted' AND observed<=? AND expires>? ORDER BY generation DESC LIMIT 1",(p['id'],x['at'],x['at']))
        if not observation or observation['profile_generation']!=p['generation']:
            return {'decision':'destination_unresolved'}
        allocated=one(db,"SELECT COALESCE(SUM(limit_bytes-used),0) n FROM egress_grants WHERE window=? AND state='active'",(x['window'],))['n']
        if x['limit_bytes']<=0 or allocated+w['used']+x['limit_bytes']>w['capacity']:
            return {'decision':'quota_overcommitted'}
        db.execute('INSERT INTO egress_grants VALUES(?,?,?,?,?,?,?,?)',(x['id'],x['contract'],x['window'],x['holder'],x['limit_bytes'],0,1,'active'))
        return {'decision':'grant_issued'}
    if op=='revoke':
        g=one(db,'SELECT * FROM egress_grants WHERE id=?',(x['id'],))
        if not g or x['generation']<=g['generation']:return {'decision':'stale_revoke'}
        db.execute("UPDATE egress_grants SET state='revoked',generation=? WHERE id=?",(x['generation'],x['id']))
        db.execute("UPDATE flow_attempts SET status='isolated' WHERE grant=? AND status='admitted'",(x['id'],))
        return {'decision':'revoked'}
    if op=='transfer':
        g=one(db,'SELECT * FROM egress_grants WHERE id=?',(x['id'],))
        if not g or g['state']!='active' or g['holder']!=x['from_holder'] or x['generation']<=g['generation']:
            return {'decision':'transfer_denied'}
        db.execute('UPDATE egress_grants SET holder=?,generation=? WHERE id=?',(x['to_holder'],x['generation'],x['id']))
        return {'decision':'transferred'}
    return {'decision':'unknown_operation'}

def run(db,x):return act(db,'permit',x,handle)
