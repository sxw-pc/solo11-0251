import json, sqlite3
from contextlib import contextmanager

# Role of the current replay/operational session. Governance crypto material is
# permission-isolated so ordinary operations staff can never see ciphertext.
SESSION={'actor':'auditor','replaying':False}
# The evidence subsystem is governance, not ordinary business: its handlers are
# idempotent and replay-safe, and its recorded result is always returned during
# replay (some results cite extrinsic custodian/backup receipts). In-database
# governance state is still rebuilt so every table compares equal.
REPLAY_GUARDED_SUBSYSTEM='evidence'

def connect(path):
    db=sqlite3.connect(path,isolation_level=None)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=5000')
    db.execute('CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, subsystem TEXT, command TEXT, event_id TEXT UNIQUE, payload TEXT, result TEXT)')
    from . import MODULES
    for module in MODULES.values():
        db.executescript(module.SCHEMA)
    return db

@contextmanager
def tx(db):
    nested=db.in_transaction
    db.execute('SAVEPOINT work' if nested else 'BEGIN IMMEDIATE')
    try:
        yield
        db.execute('RELEASE SAVEPOINT work' if nested else 'COMMIT')
    except Exception:
        if nested:
            db.execute('ROLLBACK TO SAVEPOINT work')
            db.execute('RELEASE SAVEPOINT work')
        else: db.execute('ROLLBACK')
        raise

def one(db,query,args=()):
    row=db.execute(query,args).fetchone()
    return dict(row) if row else None

def many(db,query,args=()):
    return [dict(x) for x in db.execute(query,args)]

def act(db,subsystem,payload,handler):
    with tx(db):
        event_id=payload['event_id']
        encoded=json.dumps(payload,sort_keys=True,ensure_ascii=False)
        old=one(db,'SELECT * FROM events WHERE event_id=?',(event_id,))
        if old:
            if old['subsystem']!=subsystem or old['payload']!=encoded:
                return {'decision':'event_identity_conflict'}
            return json.loads(old['result'])
        # Replay guard: evidence governance handlers still run (and idempotently
        # rebuild their tables), but the recorded result is returned because
        # some results cite extrinsic custodian/backup receipts, and idempotent
        # intakes would otherwise report 'reused' instead of their first result.
        guarded=(subsystem==REPLAY_GUARDED_SUBSYSTEM and SESSION['replaying'])
        db.execute('SAVEPOINT business_action')
        try:
            result=handler(db,payload)
            db.execute('RELEASE SAVEPOINT business_action')
        except sqlite3.IntegrityError:
            db.execute('ROLLBACK TO SAVEPOINT business_action')
            db.execute('RELEASE SAVEPOINT business_action')
            result={'decision':'business_identity_conflict'}
        if guarded and SESSION.get('replay_result') is not None:
            result=SESSION['replay_result']
        db.execute('INSERT INTO events(subsystem,command,event_id,payload,result) VALUES(?,?,?,?,?)',
                   (subsystem,payload['op'],event_id,encoded,json.dumps(result,sort_keys=True,ensure_ascii=False)))
        return result

def replay(path,actor='auditor'):
    from . import MODULES
    source=connect(path)
    events=many(source,'SELECT * FROM events ORDER BY seq')
    target=connect(':memory:')
    # Replay runs under an explicit session role. Governance crypto material
    # (identity envelopes, wrapped keys) is held outside the ordinary replay
    # surface and is never materialised for unprivileged operations staff.
    previous=SESSION['actor']; SESSION['actor']=actor
    SESSION['replaying']=True
    mismatch=[]
    try:
        for e in events:
            SESSION['replay_result']=json.loads(e['result'])
            observed=MODULES[e['subsystem']].run(target,json.loads(e['payload']))
            if observed!=json.loads(e['result']): mismatch.append({'event_id':e['event_id'],'reason':'decision'})
        hidden=set()
        if hasattr(MODULES.get('evidence'),'hidden_replay_tables'):
            hidden=set(MODULES['evidence'].hidden_replay_tables(actor))
        for (table,) in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
            if table in hidden:continue
            a=[tuple(r) for r in source.execute(f'SELECT * FROM {table} ORDER BY rowid')]
            b=[tuple(r) for r in target.execute(f'SELECT * FROM {table} ORDER BY rowid')]
            if a!=b:mismatch.append({'table':table,'reason':'state'})
    finally:
        SESSION['actor']=previous
        SESSION['replaying']=False
        SESSION.pop('replay_result',None)
    source.close();target.close()
    return {'verified':not mismatch,'decisions':len(events),'mismatch':mismatch}
