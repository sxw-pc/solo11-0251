import json, sqlite3, sys
from contextlib import contextmanager

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
    # DDL inside an open transaction would auto-commit it and release the
    # savepoints below, so every module's schema must exist before tx() opens.
    module=sys.modules.get(handler.__module__)
    if module is not None and hasattr(module,'ensure_schema'):
        module.ensure_schema(db)
    else:
        from . import MODULES
        for mod in MODULES.values():
            if hasattr(mod,'SCHEMA'):
                db.executescript(mod.SCHEMA)
    with tx(db):
        event_id=payload['event_id']
        encoded=json.dumps(payload,sort_keys=True,ensure_ascii=False)
        old=one(db,'SELECT * FROM events WHERE event_id=?',(event_id,))
        if old:
            if old['subsystem']!=subsystem or old['payload']!=encoded:
                return {'decision':'event_identity_conflict'}
            return json.loads(old['result'])
        db.execute('SAVEPOINT business_action')
        try:
            result=handler(db,payload)
            db.execute('RELEASE SAVEPOINT business_action')
        except sqlite3.IntegrityError:
            db.execute('ROLLBACK TO SAVEPOINT business_action')
            db.execute('RELEASE SAVEPOINT business_action')
            result={'decision':'business_identity_conflict'}
        db.execute('INSERT INTO events(subsystem,command,event_id,payload,result) VALUES(?,?,?,?,?)',
                   (subsystem,payload['op'],event_id,encoded,json.dumps(result,sort_keys=True,ensure_ascii=False)))
        return result

def replay(path):
    from . import MODULES
    source=connect(path)
    events=many(source,'SELECT * FROM events ORDER BY seq')
    target=connect(':memory:')
    mismatch=[]
    for e in events:
        observed=MODULES[e['subsystem']].run(target,json.loads(e['payload']))
        if observed!=json.loads(e['result']): mismatch.append({'event_id':e['event_id'],'reason':'decision'})
    for (table,) in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"):
        a=[tuple(r) for r in source.execute(f'SELECT * FROM {table} ORDER BY rowid')]
        b=[tuple(r) for r in target.execute(f'SELECT * FROM {table} ORDER BY rowid')]
        if a!=b:mismatch.append({'table':table,'reason':'state'})
    source.close();target.close()
    return {'verified':not mismatch,'decisions':len(events),'mismatch':mismatch}
