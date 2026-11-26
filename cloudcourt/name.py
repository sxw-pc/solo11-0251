from .store import act,one
SCHEMA='''
CREATE TABLE IF NOT EXISTS destination_profiles(id TEXT PRIMARY KEY,tenant TEXT,host TEXT,generation INTEGER,state TEXT);
CREATE TABLE IF NOT EXISTS resolver_policies(id TEXT PRIMARY KEY,tenant TEXT,source TEXT,generation INTEGER,state TEXT);
CREATE TABLE IF NOT EXISTS dns_observations(id TEXT PRIMARY KEY,profile TEXT,resolver_id TEXT,resolver_generation INTEGER,source TEXT,ip TEXT,generation INTEGER,profile_generation INTEGER,observed INTEGER,expires INTEGER,state TEXT);
'''

def handle(db,x):
    op=x['op']
    if op=='profile':
        old=one(db,'SELECT * FROM destination_profiles WHERE id=?',(x['id'],))
        if old and (old['tenant']!=x['tenant'] or old['host']!=x['host']):return {'decision':'profile_identity_conflict'}
        if old and x['generation']<=old['generation']:return {'decision':'stale_profile'}
        db.execute('INSERT INTO destination_profiles VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,state=excluded.state',(x['id'],x['tenant'],x['host'],x['generation'],x.get('state','active')))
        return {'decision':'profile_active' if x.get('state','active')=='active' else 'profile_disabled'}
    if op=='resolver':
        old=one(db,'SELECT * FROM resolver_policies WHERE id=?',(x['id'],))
        if old and x['generation']<=old['generation']:return {'decision':'stale_resolver'}
        state=x.get('state','active')
        if state not in ('active','revoked'):return {'decision':'invalid_resolver_state'}
        db.execute('INSERT INTO resolver_policies VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET tenant=excluded.tenant,source=excluded.source,generation=excluded.generation,state=excluded.state',(x['id'],x['tenant'],x['source'],x['generation'],state))
        return {'decision':'resolver_active' if state=='active' else 'resolver_revoked'}
    if op=='observe':
        profile=one(db,'SELECT * FROM destination_profiles WHERE id=?',(x['profile'],))
        resolver=one(db,'SELECT * FROM resolver_policies WHERE id=?',(x['resolver'],))
        if not profile or profile['state']!='active' or not resolver or resolver['state']!='active' or profile['tenant']!=resolver['tenant'] or resolver['source']!=x['source']:
            return {'decision':'untrusted_resolver'}
        if x['expires']<=x['observed']:return {'decision':'invalid_ttl'}
        latest=one(db,'SELECT MAX(generation) generation FROM dns_observations WHERE profile=?',(x['profile'],))
        if latest and latest['generation'] is not None and x['generation']<=latest['generation']:
            return {'decision':'stale_dns_answer'}
        db.execute('INSERT INTO dns_observations VALUES(?,?,?,?,?,?,?,?,?,?,?)',(x['id'],x['profile'],resolver['id'],resolver['generation'],x['source'],x['ip'],x['generation'],profile['generation'],x['observed'],x['expires'],'accepted'))
        return {'decision':'answer_accepted'}
    if op=='isolate':
        o=one(db,'SELECT * FROM dns_observations WHERE id=?',(x['id'],))
        if not o:return {'decision':'unknown_answer'}
        db.execute("UPDATE dns_observations SET state='isolated' WHERE id=?",(x['id'],))
        db.execute("UPDATE dns_pins SET state='isolated' WHERE observation=?",(x['id'],))
        return {'decision':'answer_isolated'}
    if op=='review':
        p=one(db,'SELECT * FROM destination_profiles WHERE id=?',(x['profile'],))
        if not p:return {'decision':'unknown_profile'}
        suspicious=one(db,"SELECT 1 FROM flow_attempts f JOIN dns_pins pin ON pin.id=f.pin WHERE pin.profile=? AND f.status='suspicious' LIMIT 1",(x['profile'],))
        if not suspicious:return {'decision':'no_suspicious_flow'}
        db.execute("UPDATE destination_profiles SET state='isolated' WHERE id=?",(x['profile'],))
        db.execute("UPDATE dns_observations SET state='isolated' WHERE profile=?",(x['profile'],))
        db.execute("UPDATE dns_pins SET state='isolated' WHERE profile=?",(x['profile'],))
        db.execute("UPDATE egress_grants SET state='revoked' WHERE contract IN (SELECT id FROM purpose_contracts WHERE profile=?) AND state='active'",(x['profile'],))
        return {'decision':'destination_quarantined'}
    return {'decision':'unknown_operation'}

def run(db,x):
    from .tokens import shape
    return shape(act(db,'name',x,handle))
