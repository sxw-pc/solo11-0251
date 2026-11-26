from .store import act,one,many
SCHEMA='''
CREATE TABLE IF NOT EXISTS purpose_contracts(id TEXT PRIMARY KEY,tenant TEXT,profile TEXT,purpose TEXT,generation INTEGER,state TEXT);
CREATE TABLE IF NOT EXISTS quota_windows(id TEXT PRIMARY KEY,tenant TEXT,capacity INTEGER,used INTEGER,start INTEGER,expires INTEGER,held INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS egress_grants(id TEXT PRIMARY KEY,contract TEXT,window TEXT,holder TEXT,limit_bytes INTEGER,used INTEGER,generation INTEGER,state TEXT,held INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS dispute_arbitrators(id TEXT PRIMARY KEY,tenant TEXT,actor TEXT,role TEXT,generation INTEGER,expires INTEGER,state TEXT);
CREATE TABLE IF NOT EXISTS quota_releases(id TEXT PRIMARY KEY,grant TEXT,window TEXT,flow TEXT,bytes INTEGER,kind TEXT,at INTEGER,ref TEXT);
'''

MIGRATIONS=[
    ('quota_windows','held','INTEGER NOT NULL DEFAULT 0'),
    ('egress_grants','held','INTEGER NOT NULL DEFAULT 0'),
]

OP_ALIASES={
    'release_quota':'release','release_reservation':'release',
    'free_quota':'release','reallocate':'release','release_bytes':'release',
    'availability':'balance','quota_status':'balance','available':'balance',
    'quota_balance':'balance',
}

def nz(row,key):
    try:return row[key] or 0
    except (IndexError,KeyError):return 0

def open_reserved(db,f):
    """Reservation bytes still occupying grant headroom on an open flow.

    ``reserved`` is the immutable admission reservation.  Billed bytes are
    already counted in ``egress_grants.used``; released bytes were given back
    explicitly; clawed-back billed bytes are added back symmetrically.
    """
    if not f or f['status']!='admitted':return 0
    n=f['reserved']-nz(f,'billed')+nz(f,'clawed')-nz(f,'released')
    return max(0,n)

def grant_committed(db,g):
    if not g:return 0
    row=one(db,"SELECT COALESCE(SUM(reserved-COALESCE(billed,0)+COALESCE(clawed,0)-COALESCE(released,0)),0) n FROM flow_attempts WHERE grant=? AND status='admitted'",(g['id'],))
    return nz(g,'used')+row['n']

def grant_available(db,g):
    return g['limit_bytes']-grant_committed(db,g)

def window_available(db,w):
    if not w:return None
    allocated=one(db,"SELECT COALESCE(SUM(limit_bytes-used),0) n FROM egress_grants WHERE window=? AND state='active'",(w['id'],))['n']
    return w['capacity']-(allocated+w['used'])

def apply_charge(db,f,amount):
    """Post ``amount`` settled bytes to flow/grant/window balances once."""
    if amount<=0:return
    g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],))
    db.execute('UPDATE flow_attempts SET billed=COALESCE(billed,0)+?, settled=COALESCE(settled,0)+? WHERE id=?',(amount,amount,f['id']))
    if g:
        db.execute('UPDATE egress_grants SET used=used+? WHERE id=?',(amount,g['id']))
        db.execute('UPDATE quota_windows SET used=used+? WHERE id=?',(amount,g['window']))

def apply_release(db,f,amount):
    """Give back ``amount`` bytes of the open reservation. Bounded & additive."""
    amount=max(0,int(amount))
    if amount<=0:return 0
    fresh=one(db,'SELECT * FROM flow_attempts WHERE id=?',(f['id'],))
    available=open_reserved(db,fresh or f)
    amount=min(amount,available)
    if amount:
        db.execute('UPDATE flow_attempts SET released=COALESCE(released,0)+? WHERE id=?',(amount,f['id']))
    return amount

def adjust_hold(db,f,delta):
    """Move a bounded disputed amount onto grant/window held columns."""
    if not delta:return
    g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],))
    db.execute('UPDATE flow_attempts SET held=MAX(0,COALESCE(held,0)+?), disputed=MAX(0,COALESCE(disputed,0)+?) WHERE id=?',
               (delta,delta,f['id']))
    if g:
        db.execute('UPDATE egress_grants SET held=MAX(0,COALESCE(held,0)+?) WHERE id=?',(delta,g['id']))
        db.execute('UPDATE quota_windows SET held=MAX(0,COALESCE(held,0)+?) WHERE id=?',(delta,g['window']))

def apply_clawback(db,f,amount):
    """Reverse previously billed bytes and free their reservation slot."""
    amount=max(0,int(amount))
    if amount<=0:return 0
    fresh=one(db,'SELECT * FROM flow_attempts WHERE id=?',(f['id'],))
    src=fresh or f
    billed_net=nz(src,'billed')-nz(src,'clawed')
    amount=min(amount,max(0,billed_net))
    if amount<=0:return 0
    g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],))
    db.execute('UPDATE flow_attempts SET clawed=COALESCE(clawed,0)+?, released=COALESCE(released,0)+? WHERE id=?',(amount,amount,f['id']))
    if g:
        db.execute('UPDATE egress_grants SET used=MAX(0,used-?) WHERE id=?',(amount,g['id']))
        db.execute('UPDATE quota_windows SET used=MAX(0,used-?) WHERE id=?',(amount,g['window']))
    return amount

def _release_op(db,x):
    fid=x.get('flow') or x.get('flow_id') or x.get('attempt') or x.get('attempt_id')
    f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(fid,)) if fid else None
    if not f:return {'decision':'unknown_flow'}
    if f['status'] in ('isolated','revoked'):
        return {'decision':'nothing_to_release','reason':'grant_revoked_already_freed','flow':fid,'bytes':0}
    raw=x.get('bytes',x.get('amount',x.get('release_bytes')))
    open_amount=open_reserved(db,f)
    amount=open_amount if raw is None else int(raw)
    if amount<0:return {'decision':'invalid_release'}
    if open_amount<=0:
        return {'decision':'nothing_to_release','flow':fid,'bytes':0}
    if amount>open_amount:
        return {'decision':'release_exceeds_reservation','requested':amount,'releasable':open_amount}
    released=apply_release(db,f,amount)
    g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],))
    rid=x.get('id') or x['event_id']
    db.execute('INSERT INTO quota_releases VALUES(?,?,?,?,?,?,?,?)',
               (rid,f['grant'],g['window'] if g else None,fid,released,
                x.get('kind','reservation_release'),x.get('at'),x.get('ref')))
    fresh=one(db,'SELECT * FROM flow_attempts WHERE id=?',(fid,))
    available=grant_available(db,g) if g else None
    return {'decision':'quota_released','flow':fid,'bytes':released,
            'released_total':nz(fresh,'released'),
            'available':available,'grant_available':available}

def _balance_op(db,x):
    gid=x.get('grant') or x.get('grant_id') or x.get('id')
    g=one(db,'SELECT * FROM egress_grants WHERE id=?',(gid,)) if gid else None
    if not g:return {'decision':'unknown_grant'}
    w=one(db,'SELECT * FROM quota_windows WHERE id=?',(g['window'],))
    return {'decision':'balance_reported','grant':gid,'used':g['used'],
            'limit_bytes':g['limit_bytes'],'committed':grant_committed(db,g),
            'held':nz(g,'held'),
            'available':grant_available(db,g),'window':g['window'],
            'window_used':w['used'] if w else None,
            'window_held':nz(w,'held') if w else None,
            'window_capacity':w['capacity'] if w else None,
            'window_available':window_available(db,w) if w else None}

def handle(db,x):
    op=OP_ALIASES.get(x['op'],x['op'])
    x=dict(x);x['op']=op
    if op=='purpose':
        p=one(db,'SELECT * FROM destination_profiles WHERE id=?',(x['profile'],))
        if not p or p['tenant']!=x['tenant'] or p['state']!='active':return {'decision':'profile_unavailable'}
        db.execute('INSERT INTO purpose_contracts VALUES(?,?,?,?,?,?)',(x['id'],x['tenant'],x['profile'],x['purpose'],1,'active'))
        return {'decision':'purpose_approved'}
    if op=='quota':
        if x['capacity']<=0 or x['expires']<=x['start']:return {'decision':'invalid_window'}
        db.execute('INSERT INTO quota_windows(id,tenant,capacity,used,start,expires) VALUES(?,?,?,0,?,?)',(x['id'],x['tenant'],x['capacity'],x['start'],x['expires']))
        return {'decision':'window_open'}
    if op=='grant':
        c=one(db,'SELECT * FROM purpose_contracts WHERE id=?',(x['contract'],))
        w=one(db,'SELECT * FROM quota_windows WHERE id=?',(x['window'],))
        p=one(db,'SELECT * FROM destination_profiles WHERE id=?',(c['profile'],)) if c else None
        if not c or c['state']!='active' or not p or p['state']!='active' or not w or w['tenant']!=c['tenant'] or not w['start']<=x['at']<w['expires']:
            return {'decision':'grant_unavailable'}
        observation=one(db,"SELECT * FROM dns_observations WHERE profile=? AND state='accepted' AND observed<=? AND expires>? ORDER BY generation DESC LIMIT 1",(p['id'],x['at'],x['at']))
        resolver=one(db,'SELECT * FROM resolver_policies WHERE id=?',(observation['resolver_id'],)) if observation else None
        if not observation or observation['profile_generation']!=p['generation'] or not resolver or resolver['state']!='active' or resolver['generation']!=observation['resolver_generation']:
            return {'decision':'destination_unresolved'}
        allocated=one(db,"SELECT COALESCE(SUM(limit_bytes-used),0) n FROM egress_grants WHERE window=? AND state='active'",(x['window'],))['n']
        if x['limit_bytes']<=0 or allocated+w['used']+x['limit_bytes']>w['capacity']:
            return {'decision':'quota_overcommitted'}
        db.execute('''INSERT INTO egress_grants
            (id,contract,window,holder,limit_bytes,used,generation,state)
            VALUES(?,?,?,?,?,0,1,'active')''',(x['id'],x['contract'],x['window'],x['holder'],x['limit_bytes']))
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
    if op=='arbitrator':
        if x['role']!='auditor' or x['expires']<=x['at'] or not x['actor']:
            return {'decision':'invalid_arbitrator'}
        old=one(db,'SELECT * FROM dispute_arbitrators WHERE id=?',(x['id'],))
        if old and x['generation']<=old['generation']:return {'decision':'stale_arbitrator'}
        state=x.get('state','active')
        if state not in ('active','expired','revoked'):state='active'
        db.execute('INSERT INTO dispute_arbitrators VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET tenant=excluded.tenant,actor=excluded.actor,role=excluded.role,generation=excluded.generation,expires=excluded.expires,state=excluded.state',(x['id'],x['tenant'],x['actor'],x['role'],x['generation'],x['expires'],state))
        return {'decision':'arbitrator_registered'}
    if op=='release':
        return _release_op(db,x)
    if op=='balance':
        return _balance_op(db,x)
    return {'decision':'unknown_operation'}

def run(db,x):
    from .tokens import shape
    return shape(act(db,'permit',x,handle))
