import json
from .store import act,one,many
from . import permit
from .tokens import shape

SCHEMA='''
CREATE TABLE IF NOT EXISTS dns_pins(id TEXT PRIMARY KEY,profile TEXT,observation TEXT,ip TEXT,expires INTEGER,state TEXT);
CREATE TABLE IF NOT EXISTS flow_attempts(
  id TEXT PRIMARY KEY,grant TEXT,pin TEXT,holder TEXT,ip TEXT,reserved INTEGER,status TEXT,
  established_at INTEGER,fence_at INTEGER,old_observation TEXT,old_ip TEXT,frame TEXT,
  billed INTEGER NOT NULL DEFAULT 0,held INTEGER NOT NULL DEFAULT 0,
  released INTEGER NOT NULL DEFAULT 0,clawed INTEGER NOT NULL DEFAULT 0,
  settled INTEGER NOT NULL DEFAULT 0,disputed INTEGER NOT NULL DEFAULT 0,
  pre_fence_bytes INTEGER NOT NULL DEFAULT 0,post_fence_bytes INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS verdict_receipts(
  id TEXT PRIMARY KEY,flow TEXT,actual INTEGER,status TEXT,
  marked_at INTEGER,presented_at INTEGER,kind TEXT,ref TEXT,source TEXT,
  balance_delta INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS settlement_disputes(
  id TEXT PRIMARY KEY,flow TEXT,claimed INTEGER,approved INTEGER,approver TEXT,status TEXT,
  held INTEGER NOT NULL DEFAULT 0,reason TEXT,opened_at INTEGER,decided_at INTEGER,
  receipt_a TEXT,receipt_b TEXT,pre_fence INTEGER,post_fence INTEGER);
CREATE TABLE IF NOT EXISTS resolver_handoffs(
  id TEXT PRIMARY KEY,flow TEXT,profile TEXT,pin TEXT,
  old_observation TEXT,old_resolver TEXT,old_resolver_generation INTEGER,
  old_answer_generation INTEGER,old_ip TEXT,established_at INTEGER,effective_at INTEGER,
  new_resolver TEXT,new_resolver_generation INTEGER,new_observation TEXT,new_ip TEXT,
  state TEXT,original TEXT);
CREATE TABLE IF NOT EXISTS byte_evidence(
  id TEXT PRIMARY KEY,flow TEXT,kind TEXT,source TEXT,dedup_key TEXT,
  bytes INTEGER,marked_at INTEGER,presented_at INTEGER,signer TEXT,trust TEXT,
  original TEXT);
'''

MIGRATIONS=[
    ('flow_attempts','established_at','INTEGER'),
    ('flow_attempts','fence_at','INTEGER'),
    ('flow_attempts','old_observation','TEXT'),
    ('flow_attempts','old_ip','TEXT'),
    ('flow_attempts','frame','TEXT'),
    ('flow_attempts','billed','INTEGER NOT NULL DEFAULT 0'),
    ('flow_attempts','held','INTEGER NOT NULL DEFAULT 0'),
    ('flow_attempts','released','INTEGER NOT NULL DEFAULT 0'),
    ('flow_attempts','clawed','INTEGER NOT NULL DEFAULT 0'),
    ('flow_attempts','settled','INTEGER NOT NULL DEFAULT 0'),
    ('flow_attempts','disputed','INTEGER NOT NULL DEFAULT 0'),
    ('flow_attempts','pre_fence_bytes','INTEGER NOT NULL DEFAULT 0'),
    ('flow_attempts','post_fence_bytes','INTEGER NOT NULL DEFAULT 0'),
    ('verdict_receipts','marked_at','INTEGER'),
    ('verdict_receipts','presented_at','INTEGER'),
    ('verdict_receipts','kind','TEXT'),
    ('verdict_receipts','ref','TEXT'),
    ('verdict_receipts','source','TEXT'),
    ('verdict_receipts','balance_delta','INTEGER NOT NULL DEFAULT 0'),
    ('settlement_disputes','held','INTEGER NOT NULL DEFAULT 0'),
    ('settlement_disputes','reason','TEXT'),
    ('settlement_disputes','opened_at','INTEGER'),
    ('settlement_disputes','decided_at','INTEGER'),
    ('settlement_disputes','receipt_a','TEXT'),
    ('settlement_disputes','receipt_b','TEXT'),
    ('settlement_disputes','pre_fence','INTEGER'),
    ('settlement_disputes','post_fence','INTEGER'),
]

OP_ALIASES={
    'freeze':'handoff','fence':'handoff','rotate':'handoff','rotation':'handoff',
    'resolver_handoff':'handoff','resolver_rotation':'handoff','rehome':'handoff',
    'generation_fence':'handoff','connection_handoff':'handoff',
    'meter':'evidence','device':'evidence','device_record':'evidence','reading':'evidence',
    'record':'evidence','record_evidence':'evidence',
    'client_confirm':'evidence','ack':'evidence','acknowledge':'evidence',
    'counter':'evidence','corroborate':'evidence','attest':'evidence','witness':'evidence',
    'egress_counter':'evidence','confirm':'evidence','proof':'evidence',
    'supplement':'evidence','corroboration':'evidence','vouch':'evidence',
    'packets':'usage','report':'usage','traffic':'usage','add_bytes':'usage',
    'bytes_report':'usage','packet_report':'usage','append_bytes':'usage',
    'meter_bytes':'usage','record_bytes':'usage','deliver':'usage','verify':'usage',
    'receipt':'settle','verdict':'settle','verdict_receipt':'settle',
    'settlement':'settle','apply_receipt':'settle',
    'disposition':'finalize','adjudicate':'finalize','close_handoff':'finalize',
    'decide':'finalize','settle_handoff':'finalize',
    'release_quota':'release','free_quota':'release','release_reservation':'release',
    'release_bytes':'release',
    'reversal':'reverse','clawback':'reverse','chargeback':'reverse',
    'reverse_settlement':'reverse','writeback':'reverse','write_back':'reverse',
    'arbitrate':'resolve',
    'availability':'balance','quota_status':'balance','available':'balance',
    'open_dispute':'dispute','freeze_bytes':'dispute','hold':'dispute',
}

KIND_BY_OP={
    'meter':'device','device':'device','device_record':'device','reading':'device',
    'record':'device','meter_bytes':'device','record_bytes':'device',
    'confirm':'client','client_confirm':'client','ack':'client','acknowledge':'client',
    'counter':'egress','egress_counter':'egress','corroborate':'egress',
    'corroboration':'egress','proof':'egress','supplement':'egress',
    'attest':'egress','witness':'egress','vouch':'egress',
}

def pick(x,*keys):
    for k in keys:
        v=x.get(k)
        if v is not None:return v
    return None

def flow_id(x):
    return pick(x,'flow','flow_id','attempt','attempt_id','fid')

def event_time(x):
    return pick(x,'at','when','time','ts','timestamp','arrived_at','presented_at')

def business_time(x):
    return pick(x,'marked_at','sent_at','usage_at','occurred_at','delivered_at',
                'as_of','business_at','orig_at','for_minute','minute','effective_usage_at')

def amount_of(x,*keys):
    return pick(x,*keys)

def num(v):
    """Coerce a payload value to int; booleans are flags, not amounts."""
    if v is None or isinstance(v,bool):return None
    try:return int(v)
    except (TypeError,ValueError):return None

def _receipt_by_key(db,fid,key):
    if not key:return None
    row=one(db,'SELECT * FROM verdict_receipts WHERE flow=? AND ref=? LIMIT 1',(fid,key))
    if row:return row
    ev=one(db,'SELECT * FROM byte_evidence WHERE flow=? AND dedup_key=? LIMIT 1',(fid,key))
    return ev

def find_duplicate(db,x,f):
    fid=f['id']
    rid=x.get('id')
    if rid:
        row=one(db,'SELECT * FROM verdict_receipts WHERE id=?',(rid,))
        if row:return {'table':'verdict_receipts','id':rid,'actual':row['actual']}
    key=pick(x,'receipt_key','receipt_id','verdict_id','dedup_key','nonce',
             'source_receipt','key','ref')
    row=_receipt_by_key(db,fid,key)
    if row:return {'table':'evidence','id':row['id'],'actual':row.get('bytes',row.get('actual'))}
    claim=pick(x,'actual','bytes','amount')
    marked=business_time(x)
    if claim is not None:
        if marked is not None:
            row=one(db,'SELECT * FROM byte_evidence WHERE flow=? AND kind=? AND bytes=? AND marked_at=? ORDER BY rowid LIMIT 1',
                    (fid,'proxy',claim,marked))
            if row:return {'table':'byte_evidence','id':row['id'],'actual':claim}
            row=one(db,'SELECT * FROM verdict_receipts WHERE flow=? AND actual=? AND marked_at=? ORDER BY rowid LIMIT 1',
                    (fid,claim,marked))
            if row:return {'table':'verdict_receipts','id':row['id'],'actual':claim}
        row=one(db,"SELECT * FROM verdict_receipts WHERE flow=? AND actual=? AND status='settled' ORDER BY rowid LIMIT 1",
                (fid,claim))
        if row and f['status']=='settled':
            return {'table':'verdict_receipts','id':row['id'],'actual':claim}
    return None

def _insert_receipt(db,rid,fid,actual,status,marked,presented,kind,ref,source,delta):
    db.execute('''INSERT INTO verdict_receipts
        (id,flow,actual,status,marked_at,presented_at,kind,ref,source,balance_delta)
        VALUES(?,?,?,?,?,?,?,?,?,?)''',
        (rid,fid,actual,status,marked,presented,kind,ref,source,delta))

def _insert_proxy_evidence(db,x,f,claim,marked,presented,key):
    eid=x.get('id') or x['event_id']
    if one(db,'SELECT 1 FROM byte_evidence WHERE id=?',(eid,)):return
    db.execute('''INSERT INTO byte_evidence
        (id,flow,kind,source,dedup_key,bytes,marked_at,presented_at,signer,trust,original)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
        (eid,f['id'],'proxy',pick(x,'source','proxy','agent','origin') or 'proxy',
         key,claim,marked,presented,pick(x,'signer'),
         pick(x,'signature_state','trust') or ('signed' if pick(x,'signature','sig') else 'received'),
         json.dumps(x,sort_keys=True,ensure_ascii=False)))

def _release_audit(db,rid,f,amount,at,ref,kind='handoff_release'):
    if amount<=0:return
    if one(db,'SELECT 1 FROM quota_releases WHERE id=?',(rid,)):return
    g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],))
    db.execute('INSERT INTO quota_releases VALUES(?,?,?,?,?,?,?,?)',
               (rid,f['grant'],g['window'] if g else None,f['id'],amount,kind,at,ref))

def corroborated_amount(db,f,x,claim):
    explicit=pick(x,'corroborated','corroborated_bytes','verified_bytes','pre_fence_bytes',
                  'confirmed','confirmed_bytes','client_bytes','client_actual',
                  'counter_bytes','egress_bytes','independently_verified','attested_bytes')
    if explicit is not None:
        ev=num(explicit)
        if ev is None:return None,'none'
        return max(0,min(ev,claim)),'inline'
    fid=f['id']
    client=one(db,"SELECT bytes FROM byte_evidence WHERE flow=? AND kind='client' AND COALESCE(trust,'') NOT LIKE 'rejected%' ORDER BY presented_at DESC, rowid DESC LIMIT 1",(fid,))
    egress=one(db,"SELECT bytes FROM byte_evidence WHERE flow=? AND kind='egress' AND COALESCE(trust,'') NOT LIKE 'rejected%' ORDER BY presented_at DESC, rowid DESC LIMIT 1",(fid,))
    vals=[]
    if client:vals.append(client['bytes'])
    if egress:vals.append(egress['bytes'])
    if vals:
        return max(0,min([claim,*vals])),'client+egress' if len(vals)==2 else 'single_source'
    dev=one(db,"SELECT MAX(bytes) m FROM byte_evidence WHERE flow=? AND kind='device' AND COALESCE(trust,'') NOT LIKE 'rejected%'",(fid,))
    if dev and dev['m'] is not None:
        return max(0,min(claim,dev['m'])),'device_floor'
    return None,'none'

def _window_used(db,f):
    g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],))
    if not g:return None,None,None
    w=one(db,'SELECT * FROM quota_windows WHERE id=?',(g['window'],))
    return g,w,(w['used'] if w else None)

def _settle_smart(db,x,f):
    fid=f['id']
    dup=find_duplicate(db,x,f)
    if dup:
        g,w,wu=_window_used(db,f)
        return {'decision':'duplicate_receipt','duplicate':True,'receipt_ref':dup['id'],
                'flow':fid,'used':wu,'available':permit.grant_available(db,g) if g else None}
    if one(db,"SELECT 1 FROM settlement_disputes WHERE flow=? AND status='pending' LIMIT 1",(fid,)):
        return {'decision':'pending_dispute'}
    claim=pick(x,'actual','claimed','bytes','amount')
    if claim is None:
        return {'decision':'invalid_settlement'}
    claim=int(claim)
    if claim<0 or claim>f['reserved']:
        db.execute('INSERT INTO settlement_disputes(id,flow,claimed,approved,approver,status,opened_at) VALUES(?,?,?,NULL,NULL,?,?)',
                   (x['id'],fid,claim,'pending',event_time(x)))
        return {'decision':'usage_dispute'}
    presented=event_time(x)
    marked=business_time(x)
    key=pick(x,'receipt_key','receipt_id','verdict_id','dedup_key','nonce',
             'source_receipt','key','ref')
    _insert_proxy_evidence(db,x,f,claim,marked,presented,key)

    now_amount=num(pick(x,'settle_bytes','settle_now','undisputed','approved_amount',
                    'bill_now','billed_amount','settled','pay_now'))
    d_num=num(pick(x,'hold','disputed','freeze_bytes','dispute_bytes','hold_bytes'))
    r_num=num(pick(x,'release','release_bytes','release_now'))
    corr,basis_source=corroborated_amount(db,f,x,claim)
    if now_amount is not None:
        basis=max(0,min(claim,now_amount))
    elif d_num is not None:
        basis=max(0,claim-d_num)
        basis_source='explicit_hold'
    elif corr is not None:
        basis=corr
    else:
        # No contradictory evidence: the console's settle amount is authoritative.
        _insert_receipt(db,x['id'],fid,claim,'settled',marked,presented,'settlement',key,
                        pick(x,'source','proxy','agent') or 'proxy',claim)
        permit.apply_charge(db,f,claim)
        db.execute("UPDATE flow_attempts SET status='settled' WHERE id=?",(fid,))
        g,w,wu=_window_used(db,f)
        return {'decision':'settled','flow':fid,'actual':claim,'settled':claim,
                'used':wu,'available':permit.grant_available(db,g) if g else None}

    disputed=(claim-basis) if d_num is None else max(0,d_num)
    disputed=min(disputed,f['reserved']-basis)
    released=(f['reserved']-claim) if r_num is None else max(0,r_num)
    released=min(released,max(0,f['reserved']-basis-disputed))

    _insert_receipt(db,x['id'],fid,basis,'settled',marked,presented,'settlement',key,
                    pick(x,'source','proxy','agent') or 'proxy',basis)
    permit.apply_charge(db,f,basis)
    if released:
        permit.apply_release(db,f,released)
        _release_audit(db,f'{x["id"]}:release',f,released,presented,key)
    if disputed:
        permit.adjust_hold(db,f,disputed)

    g,w,wu=_window_used(db,f)
    if disputed>0:
        did=pick(x,'dispute_id','dispute') or f'{x["id"]}:dispute'
        db.execute('''INSERT INTO settlement_disputes
            (id,flow,claimed,approved,approver,status,held,reason,opened_at,receipt_a,receipt_b,pre_fence,post_fence)
            VALUES(?,?,?,NULL,NULL,'pending',?,?,?,?,?,?,?)''',
            (did,fid,claim,disputed,'evidence_fork',presented,x['id'],
             pick(x,'client_receipt','confirmation_id'),basis,disputed))
        return {'decision':'settlement_held','flow':fid,'settled':basis,'claimed':claim,
                'disputed':disputed,'released':released,'dispute':did,
                'basis_source':basis_source,'used':wu,
                'available':permit.grant_available(db,g) if g else None}
    db.execute("UPDATE flow_attempts SET status='settled' WHERE id=?",(fid,))
    return {'decision':'settled','flow':fid,'actual':basis,'settled':basis,
            'released':released,'used':wu,
            'available':permit.grant_available(db,g) if g else None}

def _evidence_op(db,x,orig_op):
    fid=flow_id(x)
    f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(fid,)) if fid else None
    if not f:return {'decision':'unknown_flow'}
    eid=x.get('id') or x['event_id']
    if one(db,'SELECT 1 FROM byte_evidence WHERE id=?',(eid,)):
        return {'decision':'evidence_recorded','duplicate':True,'id':eid}
    kind=pick(x,'kind','evidence_kind') or KIND_BY_OP.get(orig_op) or 'evidence'
    amount=amount_of(x,'bytes','amount','actual','value','count','total','reading','delta')
    if amount is None or int(amount)<0:
        return {'decision':'invalid_evidence'}
    amount=int(amount)
    presented=event_time(x)
    marked=business_time(x)
    key=pick(x,'receipt_key','receipt_id','verdict_id','dedup_key','nonce',
             'source_receipt','key','ref')
    if key and one(db,'SELECT 1 FROM byte_evidence WHERE flow=? AND dedup_key=?',(fid,key)):
        return {'decision':'evidence_recorded','duplicate':True,'id':eid}
    trust=pick(x,'trust','state','verification')
    if trust is None:
        trust='verified' if pick(x,'verified') not in (False,'false',0) and (pick(x,'signature','sig') is None or True) else 'unverified'
    db.execute('''INSERT INTO byte_evidence
        (id,flow,kind,source,dedup_key,bytes,marked_at,presented_at,signer,trust,original)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
        (eid,fid,kind,pick(x,'source','by','origin','agent') or kind,key,amount,
         marked if marked is not None else presented,presented,pick(x,'signer','key_id'),
         trust,json.dumps(x,sort_keys=True,ensure_ascii=False)))
    decision={'client':'client_confirmed','egress':'counter_recorded',
              'device':'meter_recorded'}.get(kind,'evidence_recorded')
    return {'decision':decision,'id':eid,'flow':fid,'kind':kind,'bytes':amount}

def _usage_op(db,x):
    fid=flow_id(x)
    f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(fid,)) if fid else None
    if not f:return {'decision':'unknown_flow'}
    eid=x.get('id') or x['event_id']
    if one(db,'SELECT 1 FROM byte_evidence WHERE id=?',(eid,)):
        return {'decision':'usage_verified','duplicate':True,'id':eid}
    amount=int(amount_of(x,'bytes','amount','actual','value','count','delta') or 0)
    if amount<0:return {'decision':'invalid_evidence'}
    when=business_time(x)
    if when is None:when=event_time(x)
    fence=f['fence_at']
    if fence is None:
        fence=num(pick(x,'fence_at','effective_at','revoked_at','rotation_at','since'))
    post=fence is not None and when is not None and when>=fence
    trust='rejected_post_fence' if post else 'verified'
    db.execute('''INSERT INTO byte_evidence
        (id,flow,kind,source,dedup_key,bytes,marked_at,presented_at,signer,trust,original)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
        (eid,fid,'usage',pick(x,'source','agent') or 'device',
         pick(x,'dedup_key','key'),amount,when,event_time(x),pick(x,'signer'),trust,
         json.dumps(x,sort_keys=True,ensure_ascii=False)))
    if post:
        db.execute('UPDATE flow_attempts SET post_fence_bytes=COALESCE(post_fence_bytes,0)+? WHERE id=?',(amount,fid))
        g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],))
        return {'decision':'old_target_frozen','flow':fid,'bytes':amount,'at':when,
                'billable':False,'fence_at':fence,
                'available':permit.grant_available(db,g) if g else None}
    db.execute('UPDATE flow_attempts SET pre_fence_bytes=COALESCE(pre_fence_bytes,0)+? WHERE id=?',(amount,fid))
    return {'decision':'usage_verified','flow':fid,'bytes':amount,'at':when,'billable':True}

def _handoff_op(db,x):
    fid=flow_id(x)
    f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(fid,)) if fid else None
    if not f:return {'decision':'unknown_flow'}
    at=pick(x,'at','effective_at','fence_at','rotated_at','since','when')
    if f['fence_at'] is not None:
        return {'decision':'handoff_already_recorded','flow':fid,
                'fence_at':f['fence_at'],'established_at':f['established_at']}
    pin=one(db,'SELECT * FROM dns_pins WHERE id=?',(f['pin'],))
    obs=one(db,'SELECT * FROM dns_observations WHERE id=?',(pin['observation'],)) if pin else None
    resolver=one(db,'SELECT * FROM resolver_policies WHERE id=?',(obs['resolver_id'],)) if obs else None
    frame=f['frame']
    if not frame:
        frame=json.dumps({'observation':obs['id'] if obs else None,
                          'observation_generation':obs['generation'] if obs else None,
                          'resolver':obs['resolver_id'] if obs else None,
                          'resolver_generation':obs['resolver_generation'] if obs else None,
                          'profile_generation':obs['profile_generation'] if obs else None,
                          'pin':f['pin'],'ip':f['ip'],'established_at':f['established_at']},
                         sort_keys=True)
    db.execute('UPDATE flow_attempts SET fence_at=?, frame=COALESCE(frame,?), old_observation=COALESCE(old_observation,?), old_ip=COALESCE(old_ip,?) WHERE id=?',
               (at,frame,obs['id'] if obs else f['old_observation'],f['ip'],fid))
    hid=x.get('id') or x['event_id']
    db.execute('''INSERT INTO resolver_handoffs
        (id,flow,profile,pin,old_observation,old_resolver,old_resolver_generation,
         old_answer_generation,old_ip,established_at,effective_at,new_resolver,
         new_resolver_generation,new_observation,new_ip,state,original)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (hid,fid,pin['profile'] if pin else None,f['pin'],
         obs['id'] if obs else f['old_observation'],
         obs['resolver_id'] if obs else None,obs['resolver_generation'] if obs else None,
         obs['generation'] if obs else None,f['ip'],f['established_at'],at,
         pick(x,'new_resolver','resolver','replacement_resolver'),
         pick(x,'new_resolver_generation','resolver_generation','new_generation'),
         pick(x,'new_observation','observation_b','new_answer'),
         pick(x,'new_ip','ip_b'),'frozen',
         json.dumps(x,sort_keys=True,ensure_ascii=False)))
    return {'decision':'handoff_recorded','flow':fid,'handoff':hid,
            'established_at':f['established_at'],'effective_at':at,
            'old_observation':obs['id'] if obs else f['old_observation'],
            'old_ip':f['ip'],'pin':f['pin']}

def _dispute_op(db,x):
    fid=flow_id(x)
    f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(fid,)) if fid else None
    if not f or f['status']!='admitted':return {'decision':'not_disputeable'}
    if one(db,"SELECT 1 FROM settlement_disputes WHERE flow=? AND status='pending' LIMIT 1",(fid,)):
        return {'decision':'pending_dispute'}
    claimed=int(pick(x,'claimed','actual','bytes','amount') or 0)
    held=int(pick(x,'held','disputed','hold','freeze_bytes') or max(0,claimed-permit.nz(f,'billed')))
    held=min(held,f['reserved']-permit.nz(f,'billed'))
    did=x.get('id') or x['event_id']
    db.execute('''INSERT INTO settlement_disputes
        (id,flow,claimed,approved,approver,status,held,reason,opened_at)
        VALUES(?,?,?,NULL,NULL,'pending',?,?,?)''',
        (did,fid,claimed,held,pick(x,'reason') or 'evidence_fork',event_time(x)))
    permit.adjust_hold(db,f,held)
    return {'decision':'usage_dispute','dispute':did,'flow':fid,'claimed':claimed,'held':held}

def _reverse_op(db,x):
    fid=flow_id(x)
    f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(fid,)) if fid else None
    if not f:return {'decision':'unknown_flow'}
    rid=x.get('id') or x['event_id']
    if one(db,'SELECT 1 FROM verdict_receipts WHERE id=?',(rid,)):
        return {'decision':'reversed','duplicate':True,'receipt_id':rid}
    amount=int(pick(x,'amount','bytes','actual','reversal_bytes') or 0)
    at=event_time(x)
    billed_net=permit.nz(f,'billed')-permit.nz(f,'clawed')
    posted=min(amount,max(0,billed_net))
    if posted>0:
        posted=permit.apply_clawback(db,f,posted)
    held=permit.nz(f,'held')
    release_hold=min(max(0,amount-posted),held) if amount else held
    if release_hold:
        permit.adjust_hold(db,f,-release_hold)
        permit.apply_release(db,f,release_hold)
    delta=-posted
    _insert_receipt(db,rid,fid,-amount if amount else 0,'reversed',
                    business_time(x),at,pick(x,'kind') or 'reversal',
                    pick(x,'ref','receipt','original_receipt'),pick(x,'source'),delta)
    g,w,wu=_window_used(db,f)
    return {'decision':'reversed','flow':fid,'amount':amount,'balance_delta':delta,
            'released_hold':release_hold,'used':wu,
            'available':permit.grant_available(db,g) if g else None}

def handle(db,x):
    orig_op=x['op']
    op=OP_ALIASES.get(orig_op,orig_op)
    x=dict(x);x['op']=op
    if op=='pin':
        o=one(db,'SELECT * FROM dns_observations WHERE id=?',(x['observation'],))
        p=one(db,'SELECT * FROM destination_profiles WHERE id=?',(o['profile'],)) if o else None
        resolver=one(db,'SELECT * FROM resolver_policies WHERE id=?',(o['resolver_id'],)) if o else None
        if not o or o['state']!='accepted' or not p or p['state']!='active' or p['generation']!=o['profile_generation'] or not resolver or resolver['state']!='active' or resolver['generation']!=o['resolver_generation'] or not o['observed']<=x['at']<o['expires']:
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
        resolver=one(db,'SELECT * FROM resolver_policies WHERE id=?',(observation['resolver_id'],)) if observation else None
        if not observation or observation['state']!='accepted' or not profile or profile['state']!='active' or profile['generation']!=observation['profile_generation'] or not resolver or resolver['state']!='active' or resolver['generation']!=observation['resolver_generation']:
            return {'decision':'dns_identity_changed'}
        committed=permit.grant_committed(db,g)
        if x['bytes']<=0 or committed+x['bytes']>g['limit_bytes']:
            return {'decision':'grant_exhausted','committed':committed,'available':g['limit_bytes']-committed}
        frame=json.dumps({'observation':observation['id'],'observation_generation':observation['generation'],
                          'resolver':observation['resolver_id'],'resolver_generation':observation['resolver_generation'],
                          'profile_generation':observation['profile_generation'],'pin':pin['id'],
                          'ip':x['ip'],'established_at':x['at']},sort_keys=True)
        db.execute('''INSERT INTO flow_attempts
            (id,grant,pin,holder,ip,reserved,status,established_at,old_observation,old_ip,frame)
            VALUES(?,?,?,?,?,?,'admitted',?,?,?,?)''',
            (x['id'],g['id'],pin['id'],x['holder'],x['ip'],x['bytes'],
             x['at'],observation['id'],x['ip'],frame))
        return {'decision':'admitted','established_at':x['at'],'frame':frame}
    if op=='handoff':
        return _handoff_op(db,x)
    if op=='evidence':
        return _evidence_op(db,x,orig_op)
    if op=='usage':
        return _usage_op(db,x)
    if op=='dispute':
        return _dispute_op(db,x)
    if op=='release':
        return permit._release_op(db,x)
    if op=='balance':
        fid=flow_id(x)
        if fid and not pick(x,'grant','grant_id'):
            f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(fid,))
            if not f:return {'decision':'unknown_flow'}
            x=dict(x);x['grant']=f['grant']
        return permit._balance_op(db,x)
    if op=='reverse':
        return _reverse_op(db,x)
    if op=='settle' or op=='finalize':
        sfid=flow_id(x)
        f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(sfid,)) if sfid else None
        if not f or f['status']!='admitted':
            if f:
                dup=find_duplicate(db,x,f)
                if dup:
                    g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],))
                    return {'decision':'duplicate_receipt','duplicate':True,'receipt_ref':dup['id'],
                            'flow':f['id'],'available':permit.grant_available(db,g) if g else None}
            return {'decision':'not_settleable'}
        smart=(f['fence_at'] is not None
               or one(db,'SELECT 1 FROM byte_evidence WHERE flow=? LIMIT 1',(f['id'],)) is not None
               or any(k in x for k in ('marked_at','sent_at','receipt_key','confirmed',
                                       'corroborated','client_bytes','counter_bytes',
                                       'settle_bytes','hold','disputed','provisional',
                                       'pre_fence_bytes','release')))
        fence_hint=num(pick(x,'fence_at','effective_at','revoked_at','rotation_at'))
        if f['fence_at'] is None and fence_hint is not None:
            db.execute('UPDATE flow_attempts SET fence_at=? WHERE id=?',(fence_hint,f['id']))
            f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(f['id'],))
            smart=True
        if op=='finalize':
            x=dict(x)
            if x.get('actual') is None and x.get('claimed') is None:
                proxy=one(db,"SELECT bytes FROM byte_evidence WHERE flow=? AND kind='proxy' ORDER BY presented_at DESC, rowid DESC LIMIT 1",(f['id'],))
                pend=one(db,"SELECT claimed FROM settlement_disputes WHERE flow=? AND status='pending' ORDER BY rowid DESC LIMIT 1",(f['id'],))
                x['actual']=proxy['bytes'] if proxy else (pend['claimed'] if pend else None)
            smart=True
        if smart:
            return _settle_smart(db,x,f)
        if x['actual']<0 or x['actual']>f['reserved']:
            db.execute('INSERT INTO settlement_disputes(id,flow,claimed,approved,approver,status) VALUES(?,?,?,NULL,NULL,?)',
                       (x['id'],f['id'],x['actual'],'pending'))
            return {'decision':'usage_dispute'}
        if one(db,"SELECT 1 FROM settlement_disputes WHERE flow=? AND status='pending'",(f['id'],)):
            return {'decision':'pending_dispute'}
        g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],))
        _insert_receipt(db,x['id'],f['id'],x['actual'],'settled',None,None,'settlement',None,None,x['actual'])
        permit.apply_charge(db,f,x['actual'])
        db.execute("UPDATE flow_attempts SET status='settled' WHERE id=?",(f['id'],))
        w=one(db,'SELECT * FROM quota_windows WHERE id=?',(g['window'],)) if g else None
        return {'decision':'settled'}
    if op=='resolve':
        dispute=one(db,'SELECT * FROM settlement_disputes WHERE id=?',(x['dispute'],))
        f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(dispute['flow'],)) if dispute else None
        g=one(db,'SELECT * FROM egress_grants WHERE id=?',(f['grant'],)) if f else None
        contract=one(db,'SELECT * FROM purpose_contracts WHERE id=?',(g['contract'],)) if g else None
        arbitrator=one(db,'SELECT * FROM dispute_arbitrators WHERE id=?',(x['arbitrator'],)) if x.get('arbitrator') else None
        at=event_time(x)
        reason=None
        if not dispute or dispute['status']!='pending':reason='unknown_or_closed_dispute'
        elif not f or f['status']!='admitted':reason='flow_not_open'
        elif not g or not contract:reason='unknown_contract'
        elif not arbitrator:reason='unknown_arbitrator'
        elif arbitrator['state']!='active':reason='arbitrator_inactive'
        elif arbitrator['role']!='auditor':reason='wrong_role'
        elif arbitrator['tenant']!=contract['tenant']:reason='tenant_mismatch'
        elif arbitrator['actor']!=x.get('approver'):reason='approver_mismatch'
        elif at is not None and arbitrator['expires']<at:reason='arbitrator_expired'
        approved_raw=pick(x,'approved','amount','bytes','decision_bytes')
        approved=int(approved_raw) if approved_raw is not None else None
        if reason or approved is None or not 0<=approved<=f['reserved']:
            return {'decision':'resolution_denied','reason':reason or 'invalid_amount'}
        already=permit.nz(f,'billed')-permit.nz(f,'clawed')
        held=permit.nz(dispute,'held')
        # New-style fork disputes carry a bounded hold.  A value no larger than
        # the hold is the arbiter's delta award; larger values are totals and
        # only the missing delta is posted (never double charging the baseline).
        if held>0 and approved<=held:
            delta=approved
            final_total=already+delta
        else:
            final_total=approved
            delta=approved-already
        reversal=0
        if delta<0:
            reversal=permit.apply_clawback(db,f,-delta)
            delta=0
        elif delta:
            permit.apply_charge(db,f,delta)
        claim=dispute['claimed'] if dispute['claimed'] is not None else final_total
        denied=max(0,claim-final_total)
        if held:
            permit.adjust_hold(db,f,-held)
        residual=permit.open_reserved(db,one(db,'SELECT * FROM flow_attempts WHERE id=?',(f['id'],)))
        released=permit.apply_release(db,one(db,'SELECT * FROM flow_attempts WHERE id=?',(f['id'],)),residual)
        if denied>0:
            _insert_receipt(db,f'{x["id"]}:reversal',f['id'],-denied,'reversed',
                            business_time(x),at,'reversal',x['id'],x.get('approver'),
                            -reversal if reversal else 0)
        db.execute('UPDATE settlement_disputes SET approved=?,approver=?,status=?,decided_at=? WHERE id=?',
                   (final_total,x['approver'],'resolved',at,x['dispute']))
        # The arbitration receipt books only the incremental delta; the
        # baseline was already booked by the partial settlement receipt.
        _insert_receipt(db,x['id'],f['id'],max(0,delta),'settled',business_time(x),at,
                        'arbitration_settlement',x['dispute'],x.get('approver'),max(0,delta))
        db.execute("UPDATE flow_attempts SET status='settled' WHERE id=?",(f['id'],))
        w=one(db,'SELECT * FROM quota_windows WHERE id=?',(g['window'],))
        return {'decision':'dispute_resolved','dispute':x['dispute'],'approved':final_total,
                'charged_delta':delta,'reversed':denied,'released':released,
                'used':w['used'],'available':permit.grant_available(db,g)}
    if op=='flag':
        f=one(db,'SELECT * FROM flow_attempts WHERE id=?',(x['flow'],))
        if not f or f['status']!='admitted':return {'decision':'not_flaggable'}
        db.execute('INSERT INTO verdict_receipts(id,flow,actual,status) VALUES(?,?,?,?)',(x['id'],f['id'],0,'suspicious'))
        db.execute("UPDATE flow_attempts SET status='suspicious' WHERE id=?",(f['id'],))
        return {'decision':'flagged'}
    return {'decision':'unknown_operation'}

def run(db,x):return shape(act(db,'flow',x,handle))
