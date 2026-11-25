from .store import act,one
SCHEMA='''
CREATE TABLE IF NOT EXISTS dns_pins(id TEXT PRIMARY KEY,profile TEXT,observation TEXT,ip TEXT,expires INTEGER,state TEXT);
CREATE TABLE IF NOT EXISTS flow_attempts(id TEXT PRIMARY KEY,grant TEXT,pin TEXT,holder TEXT,ip TEXT,reserved INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS verdict_receipts(id TEXT PRIMARY KEY,flow TEXT,actual INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS settlement_disputes(id TEXT PRIMARY KEY,flow TEXT,claimed INTEGER,approved INTEGER,approver TEXT,status TEXT);
'''

def handle(db,x):
    op=x['op']
    if op=='pin':
        o=one(db,'SELECT * FROM dns_observations WHERE id=?',(x['observation'],))
        p=one(db,'SELECT * FROM destination_profiles WHERE id=?',(o['profile'],)) if o else None
        if not o or o['state']!='accepted' or not p or p['state']!='active' or p['generation']!=o['profile_generation'] or not o['observed']<=x['at']<o['expires']:
            return {'decision':'dns_unavailable'}
        db.execute('INSERT INTO dns_pins VALUES(?,?,?,?,?,?)',(x['id'],o['profile'],o['id'],o['ip'],o['expires'],'active'))
        return {'decision':'pinned'}
    if op=='connect':
        g=one(db,'SELECT * FROM egress_grants WHERE id=?',(x['grant'],))
        pin=one(db,'SELECT * FROM dns_pins WHERE id=?',(x['pin'],))
        c=one(db,'SELECT * FROM purpose_contracts WHERE id=?',(g['contract'],)) if g else None
        w=one(db,'SELECT * FROM quota_windows WHERE id=?',(g['window'],)) if g else None
        observation=one(db,'SELECT * FROM dns_observations WHERE id=?',(pin['observation'],)) if pin else None
        profile=one(db,'SELECT * FROM destination_profiles WHERE id=?',(pin['profile'],)) if pin else None
        if not g or g['state']!='active' or g['holder']!=x['holder'] or not pin or pin['state']!='active' or pin['ip']!=x['ip'] or pin['expires']<=x['at'] or not c or c['state']!='active' or c['profile']!=pin['profile'] or not w or not w['start']<=x['at']<w['expires']:
            return {'decision':'connection_denied'}
        if not observation or observation['state']!='accepted' or not profile or profile['state']!='active' or profile['generation']!=observation['profile_generation']:
            return {'decision':'dns_identity_changed'}
        outstanding=one(db,"SELECT COALESCE(SUM(reserved),0) n FROM flow_attempts WHERE grant=? AND status='admitted'",(g['id'],))['n']
        if x['bytes']<=0 or outstanding+g['used']+x['bytes']>g['limit_bytes']:
            return {'decision':'grant_exhausted'}
        db.execute('INSERT INTO flow_attempts VALUES(?,?,?,?,?,?,?)',(x['id'],g['id'],pin['id'],x['holder'],x['ip'],x['bytes'],'admitted'))
        return {'decision':'admitted'}
    if op=='settle':
        f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(x['flow'],))
        if not f or f['status']!='admitted':return {'decision':'not_settleable'}
        if x['actual']<0 or x['actual']>f['reserved']:
            db.execute('INSERT INTO settlement_disputes VALUES(?,?,?,?,?,?)',(x['id'],f['id'],x['actual'],None,None,'pending'))
            return {'decision':'usage_dispute'}
        if one(db,"SELECT 1 FROM settlement_disputes WHERE flow=? AND status='pending'",(f['id'],)):
            return {'decision':'pending_dispute'}
        g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],))
        db.execute('INSERT INTO verdict_receipts VALUES(?,?,?,?)',(x['id'],f['id'],x['actual'],'settled'))
        db.execute("UPDATE flow_attempts SET status='settled' WHERE id=?",(f['id'],))
        db.execute('UPDATE egress_grants SET used=used+? WHERE id=?',(x['actual'],g['id']))
        db.execute('UPDATE quota_windows SET used=used+? WHERE id=?',(x['actual'],g['window']))
        return {'decision':'settled'}
    if op=='resolve':
        dispute=one(db,'SELECT * FROM settlement_disputes WHERE id=?',(x['dispute'],))
        f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(dispute['flow'],)) if dispute else None
        if not dispute or dispute['status']!='pending' or not f or f['status']!='admitted' or not x.get('approver') or not 0<=x['approved']<=f['reserved']:
            return {'decision':'resolution_denied'}
        g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],))
        db.execute('UPDATE settlement_disputes SET approved=?,approver=?,status=? WHERE id=?',(x['approved'],x['approver'],'resolved',x['dispute']))
        db.execute('INSERT INTO verdict_receipts VALUES(?,?,?,?)',(x['id'],f['id'],x['approved'],'settled'))
        db.execute("UPDATE flow_attempts SET status='settled' WHERE id=?",(f['id'],))
        db.execute('UPDATE egress_grants SET used=used+? WHERE id=?',(x['approved'],g['id']))
        db.execute('UPDATE quota_windows SET used=used+? WHERE id=?',(x['approved'],g['window']))
        return {'decision':'dispute_resolved'}
    if op=='flag':
        f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(x['flow'],))
        if not f or f['status']!='admitted':return {'decision':'not_flaggable'}
        db.execute('INSERT INTO verdict_receipts VALUES(?,?,?,?)',(x['id'],f['id'],0,'suspicious'))
        db.execute("UPDATE flow_attempts SET status='suspicious' WHERE id=?",(f['id'],))
        return {'decision':'flagged'}
    return {'decision':'unknown_operation'}

def run(db,x):return act(db,'flow',x,handle)
