"""Evidence retention: verified erasure, scoped legal holds and audit continuity.

Two institutionally approved governance arrangements are implemented over the
same originals and the same two legal instruments:

* ``destroy`` (arrangement 1): the held flow's original chain plus the shared
  DNS observation are sealed with an independent judicial custodian; every
  identifiable byte of the deleted customer's flow is then irreversibly
  destroyed in the operational store and offline backups.  Internal replay
  consumes non-identifying *proof events*, never the original payload.

* ``crypto`` (arrangement 2): the judicial custodian holds an isolated
  encrypted copy of the shared originals; the operational store wraps the two
  flows' identities under independent per-flow keys and destroys every
  decryption right for the deleted flow.  Only the held flow's case key and
  non-identifying settlement events survive.  Legacy replay is permission
  isolated so ordinary operations staff can never see ciphertext.

Settlement amounts, ordering and verdicts always remain provable.  A late
retry can never write a redacted IP/holder back into ``events`` because
redaction markers fence any re-admission of the deleted subject.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3

from .store import act, one, many, tx, SESSION
SCHEMA = '''
CREATE TABLE IF NOT EXISTS deletion_orders(
  id TEXT PRIMARY KEY, subject TEXT, tenant TEXT, basis TEXT,
  issued_at INTEGER, state TEXT, arrangement TEXT);
CREATE TABLE IF NOT EXISTS legal_holds(
  id TEXT PRIMARY KEY, case_id TEXT, flow TEXT, agency TEXT,
  judge_scope TEXT, issued_at INTEGER, expires_at INTEGER,
  state TEXT, supersedes TEXT);
CREATE TABLE IF NOT EXISTS seals(
  id TEXT PRIMARY KEY, warrant_id TEXT, case_id TEXT, flow TEXT,
  custodian TEXT, receipt TEXT, scope TEXT, sealed_at INTEGER, state TEXT);
CREATE TABLE IF NOT EXISTS judicial_handoffs(
  id TEXT PRIMARY KEY, case_id TEXT, agency TEXT, warrant_id TEXT,
  custodian TEXT, receipt TEXT, kind TEXT, handed_at INTEGER, state TEXT);
CREATE TABLE IF NOT EXISTS key_destructions(
  id TEXT PRIMARY KEY, order_id TEXT, subject TEXT, flow TEXT,
  copies_claimed INTEGER, copies_destroyed INTEGER,
  destroyed_at INTEGER, state TEXT);
CREATE TABLE IF NOT EXISTS key_manifest(
  id TEXT PRIMARY KEY, key_id TEXT, flow TEXT, location TEXT,
  custodian TEXT, state TEXT, case_id TEXT);
CREATE TABLE IF NOT EXISTS key_material(
  key_id TEXT PRIMARY KEY, material TEXT);
CREATE TABLE IF NOT EXISTS identity_envelopes(
  id TEXT PRIMARY KEY, flow TEXT, field TEXT, ciphertext TEXT,
  key_id TEXT, case_id TEXT, state TEXT);
CREATE TABLE IF NOT EXISTS settlement_proofs(
  id TEXT PRIMARY KEY, flow TEXT, seq INTEGER, receipt TEXT,
  amount INTEGER, verdict TEXT, order_id TEXT, proof_hash TEXT);
CREATE TABLE IF NOT EXISTS redaction_markers(
  flow TEXT PRIMARY KEY, subject TEXT, order_id TEXT, arrangement TEXT,
  redacted_at INTEGER);
CREATE TABLE IF NOT EXISTS backup_manifests(
  id TEXT PRIMARY KEY, path TEXT, watermark_seq INTEGER,
  treated INTEGER, arrangement TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS redaction_recipes(
  id TEXT PRIMARY KEY, order_id TEXT, flow TEXT, arrangement TEXT,
  recipe TEXT, applied_at INTEGER);
CREATE TABLE IF NOT EXISTS governance_ledger(
  entry_id TEXT PRIMARY KEY, seq INTEGER, fingerprint TEXT UNIQUE,
  order_id TEXT, case_id TEXT, entry_type TEXT, flow TEXT, detail TEXT,
  booked_at INTEGER);
'''

# Crypto material lives under custodian/key-management control, not on the
# ordinary replay state surface: it is random per execution and never compared
# or materialised through replay.
REPLAY_EXTRINSIC_TABLES = ('identity_envelopes', 'key_manifest', 'key_material')
# Tables ordinary operations staff are explicitly denied.
OPS_DENIED_TABLES = REPLAY_EXTRINSIC_TABLES
LEDGER_TYPES = (
    'deletion_order', 'legal_hold', 'seal', 'handoff',
    'key_destruction', 'customer_receipt', 'backup_treatment',
    'redaction', 'hold_release',
)
IDENT_FIELDS = ('holder', 'ip')
PROOF_TOKEN = 'REDACTED-PROOF'
# Fixed pseudonymisation key keeps redaction tokens stable across replay while
# staying one-way: the original identifier cannot be read back from the token.
REDACTION_KEY = b'cloudcourt-governance-redaction-v1'


# --------------------------------------------------------------------------- #
# cryptography (standard library only): HMAC-SHA256 keystream + EtM tag
# --------------------------------------------------------------------------- #
def _keystream(key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(key, nonce + counter.to_bytes(8, 'big'),
                            hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def seal_bytes(key, plaintext):
    """Encrypt-then-MAC. Returns base64(nonce || tag || ciphertext)."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    nonce = secrets.token_bytes(16)
    stream = _keystream(key, nonce, len(plaintext))
    cipher = bytes(a ^ b for a, b in zip(plaintext, stream))
    tag = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
    return base64.b64encode(nonce + tag + cipher).decode('ascii')


def open_bytes(key, encoded):
    raw = base64.b64decode(encoded)
    nonce, tag, cipher = raw[:16], raw[16:48], raw[48:]
    expected = hmac.new(key, nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise PermissionError('ciphertext authentication failed')
    stream = _keystream(key, nonce, len(cipher))
    return bytes(a ^ b for a, b in zip(cipher, stream)).decode('utf-8')


# --------------------------------------------------------------------------- #
# independent judicial custodian: storage outside the operational database
# --------------------------------------------------------------------------- #
class JudicialCustodian:
    """A custodian whose store is a separate directory, not the ops DB.

    Sealing requires a case-scoped warrant; retrieving an original requires the
    same warrant.  The operations database never receives the originals.
    """

    def __init__(self, root):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def _path(self, receipt):
        return os.path.join(self.root, receipt + '.json')

    def seal(self, receipt, warrant_id, case_id, kind, payload):
        path = self._path(receipt)
        if os.path.exists(path):
            with open(path, encoding='utf-8') as fh:
                existing = json.load(fh)
            if existing['warrant_id'] != warrant_id or existing['case_id'] != case_id:
                raise PermissionError('custodian receipt reused under another warrant')
            return existing
        record = {'receipt': receipt, 'warrant_id': warrant_id,
                  'case_id': case_id, 'kind': kind, 'payload': payload}
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(record, fh, sort_keys=True, ensure_ascii=False)
        os.chmod(path, 0o600)
        return record

    def retrieve(self, receipt, warrant_id, case_id):
        path = self._path(receipt)
        if not os.path.exists(path):
            raise PermissionError('no sealed original for receipt')
        with open(path, encoding='utf-8') as fh:
            record = json.load(fh)
        if record['warrant_id'] != warrant_id or record['case_id'] != case_id:
            raise PermissionError('warrant does not cover this sealed original')
        return record['payload']

    def holds(self, receipt):
        return os.path.exists(self._path(receipt))


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _ensure(db):
    # Individual CREATE statements: executescript() would implicitly COMMIT the
    # surrounding business transaction and break its savepoint.
    for statement in SCHEMA.split(';'):
        statement = statement.strip()
        if statement:
            db.execute(statement)


def redaction_token(value):
    """Deterministic, non-identifying pseudonym, stable across replay."""
    digest = hmac.new(REDACTION_KEY, str(value).encode('utf-8'),
                      hashlib.sha256).digest()
    return 'tok-' + base64.b32encode(digest[:15]).decode('ascii').rstrip('=').lower()


def _ledger(db, order_id, case_id, entry_type, flow, detail):
    if entry_type not in LEDGER_TYPES:
        raise ValueError('unregistered ledger entry type')
    detail_json = json.dumps(detail, sort_keys=True, ensure_ascii=False)
    # Idempotent: the same booked fact never creates a second entry, so an
    # in-order replay reproduces the ledger exactly.
    fingerprint = hashlib.sha256(
        '|'.join((str(order_id), str(case_id), entry_type, str(flow),
                  detail_json)).encode('utf-8')).hexdigest()[:16]
    existing = one(db, 'SELECT entry_id FROM governance_ledger WHERE fingerprint=?',
                   (fingerprint,))
    if existing:
        return existing['entry_id']
    nxt = one(db, 'SELECT COALESCE(MAX(seq),0)+1 n FROM governance_ledger')['n']
    entry_id = 'led-%06d' % nxt
    db.execute('INSERT INTO governance_ledger VALUES(?,?,?,?,?,?,?,?,?)',
               (entry_id, nxt, fingerprint, order_id, case_id, entry_type, flow,
                detail_json, detail.get('at', 0)))
    return entry_id


def _flow_events(db, flow_id):
    """All event rows whose payload touches the given flow.

    Events already carrying the proof envelope are skipped: re-redacting them
    during an in-order replay would tokenise an existing token (double masking)
    and produce a different pseudonym from the live execution.
    """
    rows = many(db, 'SELECT seq, subsystem, command, event_id, payload, result '
                    'FROM events ORDER BY seq')
    hits = []
    for row in rows:
        payload = json.loads(row['payload'])
        if payload.get('proof_event'):
            continue
        if payload.get('id') == flow_id or payload.get('flow') == flow_id:
            hits.append((row, payload))
    return hits


def _flow_chain(db, flow_id):
    """Every identifiable fact reachable from the customer subject to receipt."""
    f = one(db, 'SELECT * FROM flow_attempts WHERE id=?', (flow_id,))
    chain = {'flow': f, 'pin': None, 'observation': None, 'profile': None,
             'grant': None, 'contract': None, 'window': None, 'receipts': [],
             'disputes': [], 'events': []}
    if not f:
        return chain
    chain['pin'] = one(db, 'SELECT * FROM dns_pins WHERE id=?', (f['pin'],))
    if chain['pin']:
        chain['observation'] = one(db, 'SELECT * FROM dns_observations WHERE id=?',
                                   (chain['pin']['observation'],))
        chain['profile'] = one(db, 'SELECT * FROM destination_profiles WHERE id=?',
                               (chain['pin']['profile'],))
    chain['grant'] = one(db, 'SELECT * FROM egress_grants WHERE id=?', (f['grant'],))
    if chain['grant']:
        chain['contract'] = one(db, 'SELECT * FROM purpose_contracts WHERE id=?',
                                (chain['grant']['contract'],))
        chain['window'] = one(db, 'SELECT * FROM quota_windows WHERE id=?',
                              (chain['grant']['window'],))
    chain['receipts'] = many(db, 'SELECT * FROM verdict_receipts WHERE flow=?',
                             (flow_id,))
    chain['disputes'] = many(db, 'SELECT * FROM settlement_disputes WHERE flow=?',
                             (flow_id,))
    chain['events'] = [
        {'event_id': row['event_id'], 'op': payload['op'],
         'ident_fields': [k for k in IDENT_FIELDS if k in payload]}
        for row, payload in _flow_events(db, flow_id)]
    return chain


def trace_subject(db, flow_id):
    """Public audit view: the full foreign-key walk for one subject."""
    return _flow_chain(db, flow_id)


def _active_hold(db, flow_id, at=None):
    row = one(db, "SELECT * FROM legal_holds WHERE flow=? AND state='active' "
                  "ORDER BY issued_at DESC", (flow_id,))
    if row and at is not None and row['expires_at'] < at:
        return None
    return row


def _flows_for_observation(db, observation_id):
    return [r['id'] for r in db.execute(
        'SELECT f.id FROM flow_attempts f JOIN dns_pins p ON p.id=f.pin '
        'WHERE p.observation=?', (observation_id,))]


def _is_shared_observation(db, observation_id):
    return len(_flows_for_observation(db, observation_id)) > 1


def hidden_replay_tables(actor):
    """Crypto material is outside replay comparison; ops cannot see it at all."""
    return list(REPLAY_EXTRINSIC_TABLES)


def authorize_table(actor, table):
    """RBAC gate used by every operational inspection of crypto tables."""
    if table in OPS_DENIED_TABLES and actor == 'ops':
        return False
    return True


def inspect_envelope(db, envelope_id, actor=None):
    actor = SESSION['actor'] if actor is None else actor
    if not authorize_table(actor, 'identity_envelopes'):
        return {'decision': 'access_denied', 'actor': actor,
                'reason': 'ciphertext_reserved_to_custodian'}
    row = one(db, 'SELECT * FROM identity_envelopes WHERE id=?', (envelope_id,))
    return {'decision': 'envelope', 'row': row} if row else \
        {'decision': 'unknown_envelope'}


# --------------------------------------------------------------------------- #
# legal hold with exact scope
# --------------------------------------------------------------------------- #
def place_hold(db, hold_id, flow_id, case_id, agency, judge_scope,
               issued_at, expires_at, supersedes=None):
    with tx(db):
        _ensure(db)
        if expires_at <= issued_at:
            return {'decision': 'invalid_hold_window'}
        old = one(db, 'SELECT * FROM legal_holds WHERE id=?', (hold_id,))
        if old:
            if (old['case_id'], old['flow']) == (case_id, flow_id):
                return {'decision': 'reused', 'hold_id': hold_id}
            return {'decision': 'hold_identity_conflict'}
        if not one(db, 'SELECT id FROM flow_attempts WHERE id=?', (flow_id,)):
            return {'decision': 'unavailable'}
        # Scope narrowing: a newer, narrower instrument replaces a broad hold.
        if supersedes:
            prior = one(db, 'SELECT * FROM legal_holds WHERE id=?', (supersedes,))
            if not prior:
                return {'decision': 'unknown_prior_hold'}
            db.execute("UPDATE legal_holds SET state='narrowed' WHERE id=?",
                       (supersedes,))
        db.execute('INSERT INTO legal_holds VALUES(?,?,?,?,?,?,?,?,?)',
                   (hold_id, case_id, flow_id, agency, judge_scope,
                    issued_at, expires_at, 'active', supersedes))
        _ledger(db, None, case_id, 'legal_hold', flow_id,
                {'at': issued_at, 'agency': agency, 'judge_scope': judge_scope,
                 'expires_at': expires_at, 'supersedes': supersedes})
        return {'decision': 'held', 'hold_id': hold_id, 'case_id': case_id,
                'scope': judge_scope, 'expires_at': expires_at}


def release_hold(db, hold_id, released_at, warrant_id):
    with tx(db):
        _ensure(db)
        held = one(db, 'SELECT * FROM legal_holds WHERE id=?', (hold_id,))
        if not held:
            return {'decision': 'unknown_hold'}
        if held['state'] != 'active':
            return {'decision': 'hold_not_active', 'state': held['state']}
        db.execute("UPDATE legal_holds SET state='released' WHERE id=?", (hold_id,))
        _ledger(db, None, held['case_id'], 'hold_release', held['flow'],
                {'at': released_at, 'warrant_id': warrant_id})
        # A released case key is withdrawn and destroyed.
        for key in many(db, "SELECT * FROM key_manifest WHERE flow=? AND state='escrowed'",
                        (held['flow'],)):
            db.execute("UPDATE key_manifest SET state='destroyed' WHERE id=?",
                       (key['id'],))
        db.execute("UPDATE identity_envelopes SET state='key_destroyed' WHERE flow=?",
                   (held['flow'],))
        return {'decision': 'hold_released', 'hold_id': hold_id,
                'case_id': held['case_id'], 'flow': held['flow']}


# --------------------------------------------------------------------------- #
# sealing originals with the independent custodian
# --------------------------------------------------------------------------- #
def _seal_flow_originals(db, custodian, warrant_id, case_id, flow_id, at,
                         seal_id, handoff_id, include_shared_observation):
    chain = _flow_chain(db, flow_id)
    if not chain['flow']:
        return {'decision': 'unavailable'}
    scope = ['flow_attempts', 'dns_pins', 'verdict_receipts',
             'settlement_disputes', 'events']
    payload = {
        'flow': chain['flow'], 'pin': chain['pin'],
        'receipts': chain['receipts'], 'disputes': chain['disputes'],
        'events': [r['event_id'] for r, _ in _flow_events(db, flow_id)]}
    if include_shared_observation and chain['observation']:
        payload['observation'] = chain['observation']
        payload['profile'] = chain['profile']
        scope.extend(['dns_observations', 'destination_profiles'])
    receipt = 'seal-' + seal_id
    # The custodian directory is extrinsic: do not touch it during replay.
    if not SESSION['replaying']:
        custodian.seal(receipt, warrant_id, case_id, 'original_chain', payload)
    db.execute('INSERT OR IGNORE INTO seals VALUES(?,?,?,?,?,?,?,?,?)',
               (seal_id, warrant_id, case_id, flow_id, custodian.root,
                receipt, ','.join(scope), at, 'sealed'))
    _ledger(db, None, case_id, 'seal', flow_id,
            {'at': at, 'receipt': receipt, 'scope': scope,
             'shared_observation': bool(include_shared_observation)})
    db.execute('INSERT OR IGNORE INTO judicial_handoffs VALUES(?,?,?,?,?,?,?,?,?)',
               (handoff_id, case_id, custodian.root, warrant_id, custodian.root,
                receipt, 'original_chain', at, 'handed'))
    _ledger(db, None, case_id, 'handoff', flow_id,
            {'at': at, 'receipt': receipt, 'warrant_id': warrant_id})
    return {'decision': 'sealed', 'seal_id': seal_id, 'receipt': receipt,
            'scope': scope}


def seal_for_court(db, custodian, seal_id, handoff_id, flow_id, warrant_id,
                   case_id, agency, at):
    """Seal the held flow's chain; include the shared observation once."""
    with tx(db):
        _ensure(db)
        existing = one(db, 'SELECT * FROM seals WHERE id=?', (seal_id,))
        if existing and not SESSION['replaying']:
            return {'decision': 'reused', 'receipt': existing['receipt']}
        chain = _flow_chain(db, flow_id)
        if SESSION['replaying']:
            # The recorded result fixes whether the shared DNS observation was
            # in scope; the in-memory graph may already have been partially
            # redacted by the time replay reaches this event.
            recorded = SESSION.get('replay_result') or {}
            shared = 'dns_observations' in recorded.get('scope', [])
        else:
            shared = bool(chain['observation'] and
                          _is_shared_observation(db, chain['observation']['id']))
        return _seal_flow_originals(db, custodian, warrant_id, case_id, flow_id,
                                    at, seal_id, handoff_id, shared)


# --------------------------------------------------------------------------- #
# arrangement 1: irreversible destruction + non-identifying proof events
# --------------------------------------------------------------------------- #
def _proof_for(payload, flow_id, order_id, mode):
    """Build a replayable proof event.

    It retains every non-identifying field of the original command so the
    owning handler can rebuild full business state (flow row, receipt, quota
    and grant effects), while holder/IP are replaced by non-identifying tokens
    (destroy) or wrapped envelope references (crypto). A proof envelope plus the
    recorded original verdict keep the replay decision identical.
    """
    proof = dict(payload)
    proof['op'] = payload['op']
    proof['proof_of'] = payload['op']
    proof['proof_event'] = True
    proof['flow_ref'] = flow_id
    proof['redaction'] = PROOF_TOKEN if mode == 'destroy' else 'WRAPPED'
    proof['order_id'] = order_id
    if mode == 'crypto':
        proof['key_id'] = 'key-' + flow_id
    for field in IDENT_FIELDS:
        if field in proof:
            proof[field] = (redaction_token(proof[field]) if mode == 'destroy'
                            else 'WRAPPED-env-%s-%s' % (flow_id, field))
    return proof


def _rewrite_events(db, flow_id, order_id, mode):
    changed = []
    for row, payload in _flow_events(db, flow_id):
        proof = _proof_for(payload, flow_id, order_id, mode)
        encoded = json.dumps(proof, sort_keys=True, ensure_ascii=False)
        # Keep the original subsystem/op so replay runs the owning handler,
        # which rebuilds state from the tokenised (identity-free) payload.
        db.execute('UPDATE events SET payload=? WHERE seq=?', (encoded, row['seq']))
        changed.append(payload['event_id'])
    return changed


def _masked_token(db, flow_id, field):
    """Recover the exact pseudonym a proof event already carries for a field."""
    for row in db.execute('SELECT payload FROM events'):
        event = json.loads(row['payload'])
        if event.get('proof_event') and (
                event.get('id') == flow_id or event.get('flow') == flow_id) \
                and field in event:
            return event[field]
    return None


def _destroy_in_db(db, flow_id, order_id, at):
    f = one(db, 'SELECT * FROM flow_attempts WHERE id=?', (flow_id,))
    if not f:
        return {'decision': 'unknown_flow'}
    if _active_hold(db, flow_id, at):
        return {'decision': 'flow_under_hold'}
    # Idempotent masking: on replay the row/event already hold pseudonyms, so
    # reuse them rather than tokenising a token (which would change the value).
    token_holder = _masked_token(db, flow_id, 'holder') or redaction_token(f['holder'])
    token_ip = _masked_token(db, flow_id, 'ip') or redaction_token(f['ip'])
    # 1. business rows: field-level masking, never row deletion
    db.execute('UPDATE flow_attempts SET holder=?, ip=? WHERE id=?',
               (token_holder, token_ip, flow_id))
    # 1b. the subject also owns the egress grant; mask its holder while keeping
    #     limit/used/window so the settled credit relationship stays provable.
    grant = one(db, 'SELECT holder FROM egress_grants WHERE id=?', (f['grant'],))
    if grant and not str(grant['holder']).startswith(('tok-', 'WRAPPED-')):
        db.execute('UPDATE egress_grants SET holder=? WHERE id=?',
                   (token_holder, f['grant']))
    # 2. raw event payloads become proof events: replay cannot re-insert IPs
    changed = _rewrite_events(db, flow_id, order_id, 'destroy')
    # 3. irreversible transaction proof preserving amount/order/verdict
    seq = 0
    for r in many(db, 'SELECT * FROM verdict_receipts WHERE flow=? ORDER BY id',
                  (flow_id,)):
        seq += 1
        proof_id = 'proof-%s-%d' % (flow_id, seq)
        digest = hashlib.sha256(
            '|'.join((flow_id, r['id'], str(r['actual']), r['status'])).encode()
        ).hexdigest()
        db.execute('INSERT OR IGNORE INTO settlement_proofs VALUES(?,?,?,?,?,?,?,?)',
                   (proof_id, flow_id, seq, r['id'], r['actual'], r['status'],
                    order_id, digest))
    db.execute('INSERT OR IGNORE INTO redaction_markers VALUES(?,?,?,?,?)',
               (flow_id, token_holder, order_id, 'destroy', at))
    return {'decision': 'destroyed', 'flow': flow_id,
            'events_rewritten': changed, 'proofs': seq}


def _order_flows(db, order):
    return [r['id'] for r in db.execute(
        'SELECT id FROM flow_attempts WHERE holder=? ORDER BY id',
        (order['subject'],))]


def _crypto_scope(db, order_flows, at):
    """Crypto separation covers the deleted subject's flows plus any flow under
    an active legal hold that shares a DNS observation with them. The held flow
    keeps its identity under its own case key; the deleted flow's key is
    destroyed."""
    scope = list(order_flows)
    for flow_id in order_flows:
        chain = _flow_chain(db, flow_id)
        obs = chain['observation']['id'] if chain['observation'] else None
        if not obs:
            continue
        for other in _flows_for_observation(db, obs):
            if other not in scope and _active_hold(db, other, at):
                scope.append(other)
    return scope


def execute_destruction(db, order_id, custodian, at, backup_paths=()):
    with tx(db):
        _ensure(db)
        order = one(db, 'SELECT * FROM deletion_orders WHERE id=?', (order_id,))
        if not order:
            return {'decision': 'unknown_order'}
        if order['arrangement'] != 'destroy':
            return {'decision': 'wrong_arrangement'}
        if one(db, 'SELECT 1 FROM redaction_markers WHERE order_id=?',
               (order_id,)) and not SESSION['replaying']:
            return {'decision': 'already_deleted'}
        already = bool(one(
            db, 'SELECT 1 FROM redaction_markers WHERE order_id=?', (order_id,)))
        # On replay the markers are only created by this very event, so recover
        # the enumerated flows from the recorded result; live execution reads
        # them from the order's original subject.
        if SESSION['replaying'] and SESSION.get('replay_result'):
            target_flows = [f['flow'] for f in
                            SESSION['replay_result'].get('flows', [])]
        else:
            target_flows = _order_flows(db, order)
        if not SESSION['replaying']:
            blocked = [fid for fid in target_flows if _active_hold(db, fid, at)]
            if blocked:
                return {'decision': 'flow_under_hold', 'flows': blocked}
        # A repeated destruction (live refusal or a later duplicate event in the
        # replay stream) must not double-book the ledger.
        if not already:
            outcomes = [_destroy_in_db(db, fid, order_id, at) for fid in target_flows]
            backup_results = [_treat_backup(db, p, order_id, 'destroy', at)
                              for p in backup_paths]
            _ledger(db, order_id, None, 'redaction', ','.join(target_flows),
                    {'at': at, 'arrangement': 'destroy', 'flows': target_flows})
            _ledger(db, order_id, None, 'customer_receipt', ','.join(target_flows),
                    {'at': at, 'receipt': 'receipt-' + order_id,
                     'retained_facts': ['amount', 'order', 'verdict']})
        else:
            outcomes, backup_results = [], []
        return {'decision': 'destruction_complete', 'flows': outcomes,
                'backups': backup_results}


# --------------------------------------------------------------------------- #
# arrangement 2: per-flow key wrapping + destruction of F2 decryption rights
# --------------------------------------------------------------------------- #
def execute_crypto_separation(db, order_id, custodian, at, backup_paths=()):
    with tx(db):
        _ensure(db)
        order = one(db, 'SELECT * FROM deletion_orders WHERE id=?', (order_id,))
        if not order:
            return {'decision': 'unknown_order'}
        if order['arrangement'] != 'crypto':
            return {'decision': 'wrong_arrangement'}
        if one(db, 'SELECT 1 FROM redaction_markers WHERE order_id=?',
               (order_id,)) and not SESSION['replaying']:
            return {'decision': 'already_deleted'}
        if SESSION['replaying'] and SESSION.get('replay_result'):
            target_flows = [w['flow'] for w in
                            SESSION['replay_result'].get('wrapped', [])]
        else:
            target_flows = _crypto_scope(db, _order_flows(db, order), at)
        wrapped = []
        for flow_id in target_flows:
            f = one(db, 'SELECT * FROM flow_attempts WHERE id=?', (flow_id,))
            if not f:
                continue
            hold = _active_hold(db, flow_id, at)
            case_id = hold['case_id'] if hold else None
            key_id = 'key-' + flow_id
            if not SESSION['replaying']:
                # Key material, manifests and envelopes are extrinsic crypto
                # state, excluded from the replay comparison surface.
                material = secrets.token_bytes(32)
                db.execute('INSERT OR REPLACE INTO key_material VALUES(?,?)',
                           (key_id, base64.b64encode(material).decode('ascii')))
                db.execute('INSERT OR IGNORE INTO key_manifest VALUES(?,?,?,?,?,?,?)',
                           ('km-ops-' + flow_id, key_id, flow_id, 'operational_db',
                            custodian.root, 'active', case_id))
                db.execute('INSERT OR IGNORE INTO key_manifest VALUES(?,?,?,?,?,?,?)',
                           ('km-copy-' + flow_id, key_id, flow_id, 'offsite_key_copy',
                            custodian.root, 'active', case_id))
                for field, value in (('holder', f['holder']), ('ip', f['ip'])):
                    env_id = 'env-%s-%s' % (flow_id, field)
                    db.execute('INSERT OR REPLACE INTO identity_envelopes '
                               'VALUES(?,?,?,?,?,?,?)',
                               (env_id, flow_id, field, seal_bytes(material, value),
                                key_id, case_id, 'wrapped'))
            for field in IDENT_FIELDS:
                db.execute('UPDATE flow_attempts SET %s=? WHERE id=?' % field,
                           ('WRAPPED-env-%s-%s' % (flow_id, field), flow_id))
            # wrap the grant's account holder too, preserving its quota facts
            grant = one(db, 'SELECT holder FROM egress_grants WHERE id=?',
                        (f['grant'],))
            if grant and not str(grant['holder']).startswith(
                    ('WRAPPED-', 'tok-')):
                db.execute('UPDATE egress_grants SET holder=? WHERE id=?',
                           ('WRAPPED-env-%s-holder' % flow_id, f['grant']))
            _rewrite_events(db, flow_id, order_id, 'crypto')
            if not SESSION['replaying']:
                custodian.seal('crypto-' + flow_id, hold['id'] if hold else order_id,
                               case_id or order_id, 'isolated_ciphertext',
                               {'flow': flow_id, 'envelopes': [
                                   'env-%s-%s' % (flow_id, x) for x in IDENT_FIELDS]})
            wrapped.append({'flow': flow_id, 'case_id': case_id,
                            'key_id': key_id, 'held': bool(hold)})
            existing_marker = one(
                db, 'SELECT subject FROM redaction_markers WHERE flow=?',
                (flow_id,))
            if existing_marker:
                marker_subject = existing_marker['subject']
            else:
                # On replay the row is already WRAPPED, so recover the pseudonym
                # the proof event recorded rather than re-tokenising the wrapper.
                marker_subject = (_masked_token(db, flow_id, 'holder')
                                  or redaction_token(f['holder']))
            db.execute('INSERT OR IGNORE INTO redaction_markers VALUES(?,?,?,?,?)',
                       (flow_id, marker_subject, order_id, 'crypto', at))
        destroyed = _destroy_keys_for_unheld(db, order, custodian, at, target_flows)
        backup_results = [_treat_backup(db, p, order_id, 'crypto', at)
                          for p in backup_paths]
        _ledger(db, order_id, None, 'redaction', ','.join(target_flows),
                {'at': at, 'arrangement': 'crypto', 'flows': target_flows})
        _ledger(db, order_id, None, 'customer_receipt', ','.join(target_flows),
                {'at': at, 'receipt': 'receipt-' + order_id,
                 'retained_facts': ['amount', 'order', 'verdict']})
        return {'decision': 'crypto_separation_complete', 'wrapped': wrapped,
                'key_destructions': destroyed, 'backups': backup_results}


def _destroy_keys_for_unheld(db, order, custodian, at, target_flows):
    results = []
    for flow_id in target_flows:
        hold = _active_hold(db, flow_id, at)
        if hold:
            # The case key survives, but only inside custodian escrow.
            if not SESSION['replaying']:
                for key in many(db, "SELECT * FROM key_manifest WHERE flow=? AND state='active'",
                                (flow_id,)):
                    db.execute("UPDATE key_manifest SET state='escrowed' WHERE id=?",
                               (key['id'],))
                material = one(db, 'SELECT material FROM key_material WHERE key_id=?',
                               ('key-' + flow_id,))
                if material:
                    custodian.seal('casekey-' + flow_id, hold['id'], hold['case_id'],
                                   'case_key', {'key_material': material['material']})
                    db.execute('DELETE FROM key_material WHERE key_id=?',
                               ('key-' + flow_id,))
            results.append({'flow': flow_id, 'decision': 'key_escrowed'})
            continue
        if SESSION['replaying']:
            # Crypto tables are extrinsic and not rebuilt during replay, so
            # recover the recorded copy count from this event's result.
            recorded = SESSION.get('replay_result') or {}
            match = next((d for d in recorded.get('key_destructions', [])
                          if d.get('flow') == flow_id), None)
            claimed = match['copies_destroyed'] if match else 0
        else:
            manifest = many(db, 'SELECT * FROM key_manifest WHERE flow=?', (flow_id,))
            claimed = len(manifest)
            for key in manifest:
                db.execute("UPDATE key_manifest SET state='destroyed' WHERE id=?",
                           (key['id'],))
            db.execute('DELETE FROM key_material WHERE key_id=?', ('key-' + flow_id,))
            db.execute("UPDATE identity_envelopes SET state='key_destroyed' WHERE flow=?",
                       (flow_id,))
        dest_id = 'kd-' + flow_id
        db.execute('INSERT OR REPLACE INTO key_destructions VALUES(?,?,?,?,?,?,?,?)',
                   (dest_id, order['id'], order['subject'], flow_id, claimed,
                    claimed, at, 'destroyed'))
        _ledger(db, order['id'], None, 'key_destruction', flow_id,
                {'at': at, 'copies_claimed': claimed,
                 'copies_destroyed': claimed})
        results.append({'flow': flow_id, 'decision': 'key_destroyed',
                        'copies_destroyed': claimed})
    return results


def verify_key_destruction(db, flow_id):
    """A flow is safely erased when every manifest copy is destroyed and no
    operational key material remains. A held flow instead has its sole key
    escrowed with the judicial custodian (not present in the operational DB)."""
    manifest = many(db, 'SELECT * FROM key_manifest WHERE flow=?', (flow_id,))
    if not manifest:
        return {'decision': 'no_keys', 'fully_destroyed': False}
    live = [m for m in manifest if m['state'] == 'active']
    escrowed = [m for m in manifest if m['state'] == 'escrowed']
    destroyed = [m for m in manifest if m['state'] == 'destroyed']
    material = one(db, 'SELECT 1 FROM key_material WHERE key_id=?',
                   ('key-' + flow_id,))
    if escrowed and not live and not material:
        return {'decision': 'key_escrowed_to_custodian', 'fully_destroyed': False,
                'copies_total': len(manifest), 'escrowed': len(escrowed),
                'operational_material': False}
    fully = not live and not material and len(destroyed) == len(manifest)
    return {'decision': 'verified' if fully else 'key_copies_remain',
            'fully_destroyed': fully, 'copies_total': len(manifest),
            'copies_live': len(live), 'operational_material': bool(material)}


def decrypt_identity(db, custodian, flow_id, field, warrant_id, case_id):
    """Only a case-scoped warrant via the custodian restores an identity."""
    env = one(db, 'SELECT * FROM identity_envelopes WHERE flow=? AND field=?',
              (flow_id, field))
    if not env:
        return {'decision': 'no_envelope'}
    if env['state'] == 'key_destroyed' or env['case_id'] != case_id:
        return {'decision': 'decryption_right_destroyed'}
    record = custodian.retrieve('casekey-' + flow_id, warrant_id, case_id)
    key = base64.b64decode(record['key_material'])
    return {'decision': 'decrypted', 'flow': flow_id, 'field': field,
            'value': open_bytes(key, env['ciphertext'])}


# --------------------------------------------------------------------------- #
# offline backups: identical treatment + restore fence
# --------------------------------------------------------------------------- #
def _live_path(db):
    return db.execute('PRAGMA database_list').fetchone()[2]


def snapshot_backup(db, backup_id, path, at):
    """Consistent file copy of the live database via the SQLite backup API."""
    with tx(db):
        _ensure(db)
        watermark = one(db, 'SELECT COALESCE(MAX(seq),0) n FROM events')['n']
        db.execute('INSERT OR REPLACE INTO backup_manifests VALUES(?,?,?,?,?,?)',
                   (backup_id, path, watermark, 0, None, at))
    if SESSION['replaying']:
        return {'decision': 'backup_manifest_rebuilt', 'backup_id': backup_id,
                'path': path, 'watermark_seq': watermark}
    live_path = _live_path(db)
    if not live_path:
        return {'decision': 'in_memory_backup_unsupported'}
    source = sqlite3.connect(live_path)
    target = sqlite3.connect(path)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    return {'decision': 'backup_snapshotted', 'backup_id': backup_id,
            'path': path, 'watermark_seq': watermark}


def _recipe_id(order_id, path):
    digest = hashlib.sha256(path.encode('utf-8')).hexdigest()[:16]
    return 'recipe-%s-%s' % (order_id, digest)


def _proof_payload(payload, flow_id, order_id, mode, decision=None):
    return _proof_for(payload, flow_id, order_id, mode)


def _treat_backup(db, path, order_id, mode, at):
    if not os.path.exists(path):
        # During an in-memory replay the offline backup file is extrinsic and
        # absent; the manifest/ledger rows still rebuild through normal replay.
        return {'path': path, 'decision': 'backup_extrinsic_skipped'}
    recipe_id = _recipe_id(order_id, path)
    order = one(db, 'SELECT * FROM deletion_orders WHERE id=?', (order_id,))
    # The live store is already redacted, so select flows by the order's
    # original subject; the backup still carries that unredacted subject.
    target_flows = [r['flow'] for r in db.execute(
        'SELECT flow FROM redaction_markers WHERE order_id=? ORDER BY flow',
        (order_id,))] or _order_flows(db, order)
    remote = sqlite3.connect(path)
    remote.row_factory = sqlite3.Row
    try:
        remote.executescript(SCHEMA)
        for flow_id in target_flows:
            f = remote.execute('SELECT * FROM flow_attempts WHERE id=?',
                               (flow_id,)).fetchone()
            if not f:
                continue
            fdict = dict(f)
            if mode == 'destroy':
                token_holder = redaction_token(fdict['holder'])
                token_ip = redaction_token(fdict['ip'])
                remote.execute('UPDATE flow_attempts SET holder=?, ip=? WHERE id=?',
                               (token_holder, token_ip, flow_id))
                remote.execute(
                    'UPDATE egress_grants SET holder=? WHERE id=? AND holder NOT LIKE ?',
                    (token_holder, fdict['grant'], 'tok-%'))
                marker_subject = token_holder
            else:
                for field in IDENT_FIELDS:
                    remote.execute('UPDATE flow_attempts SET %s=? WHERE id=?' % field,
                                   ('WRAPPED-env-%s-%s' % (flow_id, field), flow_id))
                remote.execute(
                    'UPDATE egress_grants SET holder=? WHERE id=?',
                    ('WRAPPED-env-%s-holder' % flow_id, fdict['grant']))
                marker_subject = redaction_token(fdict['holder'])
            for row in remote.execute('SELECT seq, payload, result FROM events ORDER BY seq'):
                payload = json.loads(row['payload'])
                if payload.get('id') == flow_id or payload.get('flow') == flow_id:
                    proof = _proof_payload(payload, flow_id, order_id, mode)
                    # keep the original subsystem and command on the backup
                    remote.execute(
                        'UPDATE events SET payload=? WHERE seq=?',
                        (json.dumps(proof, sort_keys=True, ensure_ascii=False),
                         row['seq']))
            remote.execute('INSERT OR IGNORE INTO redaction_markers VALUES(?,?,?,?,?)',
                           (flow_id, marker_subject, order_id, mode, at))
        remote.execute('INSERT OR REPLACE INTO redaction_recipes VALUES(?,?,?,?,?,?)',
                       (recipe_id, order_id, ','.join(target_flows), mode,
                        json.dumps({'flows': target_flows, 'arrangement': mode},
                                   sort_keys=True), at))
        remote.commit()
    finally:
        remote.close()
    db.execute('UPDATE backup_manifests SET treated=1, arrangement=? WHERE path=?',
               (mode, path))
    _ledger(db, order_id, None, 'backup_treatment', path,
            {'at': at, 'arrangement': mode, 'recipe': recipe_id})
    return {'path': path, 'decision': 'backup_treated', 'recipe': recipe_id}


def restore_backup(db, path):
    """A restore is refused unless the backup carries the deletion recipe."""
    if not os.path.exists(path):
        return {'decision': 'backup_missing'}
    remote = sqlite3.connect(path)
    remote.row_factory = sqlite3.Row
    try:
        tables = {r[0] for r in remote.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if 'redaction_recipes' not in tables or not remote.execute(
                'SELECT 1 FROM redaction_recipes LIMIT 1').fetchall():
            return {'decision': 'restore_quarantined',
                    'reason': 'untreated backup would re-introduce deleted identity'}
        recipes = [dict(r) for r in remote.execute(
            'SELECT * FROM redaction_recipes ORDER BY applied_at').fetchall()]
    finally:
        remote.close()
    return {'decision': 'restore_allowed', 'path': path, 'recipes': recipes}


# --------------------------------------------------------------------------- #
# deletion order intake
# --------------------------------------------------------------------------- #
def intake_deletion_order(db, order_id, subject, tenant, basis, issued_at,
                          arrangement):
    with tx(db):
        _ensure(db)
        old = one(db, 'SELECT * FROM deletion_orders WHERE id=?', (order_id,))
        if old and not SESSION['replaying']:
            return {'decision': 'reused', 'order_id': order_id,
                    'arrangement': old['arrangement']}
        if arrangement not in ('destroy', 'crypto'):
            return {'decision': 'unknown_arrangement'}
        if SESSION['replaying'] and SESSION.get('replay_result'):
            # Recover the originally enumerated flows; the subject's rows are
            # tokenised by later events in the replay stream.
            flows = SESSION['replay_result'].get('flows', [])
        else:
            flows = [r['id'] for r in db.execute(
                'SELECT id FROM flow_attempts WHERE holder=? ORDER BY id',
                (subject,))]
        db.execute('INSERT OR IGNORE INTO deletion_orders VALUES(?,?,?,?,?,?,?)',
                   (order_id, subject, tenant, basis, issued_at, 'open',
                    arrangement))
        _ledger(db, order_id, None, 'deletion_order', ','.join(flows),
                {'at': issued_at, 'subject': subject, 'basis': basis,
                 'arrangement': arrangement, 'flows': flows})
        return {'decision': 'order_recorded', 'order_id': order_id,
                'flows': flows, 'arrangement': arrangement}


# --------------------------------------------------------------------------- #
# audit views
# --------------------------------------------------------------------------- #
def settlement_audit(db, flow_id):
    """Amounts, sequence and verdicts remain provable without identity."""
    receipts = many(db, 'SELECT * FROM verdict_receipts WHERE flow=? ORDER BY id',
                    (flow_id,))
    proofs = many(db, 'SELECT * FROM settlement_proofs WHERE flow=? ORDER BY seq',
                  (flow_id,))
    f = one(db, 'SELECT * FROM flow_attempts WHERE id=?', (flow_id,))
    return {'flow': flow_id, 'status': f['status'] if f else None,
            'receipts': [{'receipt': r['id'], 'amount': r['actual'],
                          'verdict': r['status']} for r in receipts],
            'proofs': [{'proof': p['id'], 'amount': p['amount'],
                        'verdict': p['verdict'], 'hash': p['proof_hash']}
                       for p in proofs],
            'identifiers_present': _identifiers_present(db, flow_id)}


def _identifiers_present(db, flow_id):
    found = []
    f = one(db, 'SELECT holder, ip FROM flow_attempts WHERE id=?', (flow_id,))
    if f:
        for field in IDENT_FIELDS:
            value = f[field]
            if value and not str(value).startswith(('tok-', 'WRAPPED-')):
                found.append({'table': 'flow_attempts', 'field': field,
                              'value': value})
    for row in db.execute('SELECT payload FROM events'):
        payload = json.loads(row['payload'])
        if payload.get('flow_ref') == flow_id or payload.get('id') == flow_id \
                or payload.get('flow') == flow_id:
            for field in IDENT_FIELDS:
                value = payload.get(field)
                if isinstance(value, str) and not value.startswith(
                        ('tok-', 'WRAPPED-')):
                    found.append({'table': 'events', 'field': field,
                                  'value': value})
    return found


def ledger_entries(db, entry_type=None):
    if entry_type:
        return many(db, 'SELECT * FROM governance_ledger WHERE entry_type=? '
                        'ORDER BY seq', (entry_type,))
    return many(db, 'SELECT * FROM governance_ledger ORDER BY seq')


def custodian_verification(db, custodian, flow_id, warrant_id, case_id):
    sealed = one(db, "SELECT * FROM seals WHERE flow=? AND state='sealed'",
                 (flow_id,))
    if not sealed:
        return {'decision': 'no_seal'}
    payload = custodian.retrieve(sealed['receipt'], warrant_id, case_id)
    return {'decision': 'verified_at_custodian', 'receipt': sealed['receipt'],
            'flow': flow_id, 'tables': sealed['scope'].split(','),
            'has_original_holder': bool(payload.get('flow', {}).get('holder'))}


# --------------------------------------------------------------------------- #
# late retry fence
# --------------------------------------------------------------------------- #
def admission_fence(db, payload):
    """Block re-admission of a redacted subject so deleted IPs never return.

    A governance *proof event* (``proof_event`` flag) carries tokenised identity
    and is allowed through so replay can rebuild business state. A genuine late
    retry still carries the original holder/IP and is blocked once the subject
    has any proof event or redaction marker — even during an in-order replay
    that reaches the retry before the governance destruction event itself.
    """
    if payload.get('op') != 'connect' or payload.get('proof_event'):
        return None
    _ensure(db)
    holder = payload.get('holder')
    ip = payload.get('ip')
    holder_token = redaction_token(holder) if holder is not None else None
    ip_token = redaction_token(ip) if ip is not None else None
    # Destroy mode: a proof event carries the subject's pseudonym.
    for row in db.execute('SELECT payload FROM events'):
        event = json.loads(row['payload'])
        if not event.get('proof_event'):
            continue
        if (holder_token is not None and event.get('holder') == holder_token) or \
           (ip_token is not None and event.get('ip') == ip_token):
            return {'decision': 'subject_deleted_retry_blocked'}
    if holder_token is not None and one(
            db, 'SELECT 1 FROM redaction_markers WHERE subject=?',
            (holder_token,)):
        return {'decision': 'subject_deleted_retry_blocked'}
    if ip_token is not None and one(
            db, 'SELECT 1 FROM flow_attempts WHERE ip=?', (ip_token,)):
        return {'decision': 'subject_deleted_retry_blocked'}
    # Crypto mode: the deleted flow's row/pin are wrapped; a retry targeting the
    # same grant or pin must not re-introduce cleartext identity.
    pin_ref = payload.get('pin')
    grant_ref = payload.get('grant')
    if pin_ref or grant_ref:
        wrapped = one(
            db,
            'SELECT 1 FROM flow_attempts WHERE '
            '(holder LIKE ? OR ip LIKE ?) AND (pin=? OR grant=?) LIMIT 1',
            ('WRAPPED-%', 'WRAPPED-%', pin_ref, grant_ref))
        if wrapped:
            return {'decision': 'subject_deleted_retry_blocked'}
    return None


# --------------------------------------------------------------------------- #
# event-sourced entry point
# --------------------------------------------------------------------------- #
def run(db, x):
    return act(db, 'evidence', x, handle)


def handle(db, x):
    op = x['op']
    _ensure(db)
    if op == 'intake_order':
        return intake_deletion_order(
            db, x['order_id'], x['subject'], x['tenant'], x['basis'],
            x['issued_at'], x['arrangement'])
    if op == 'place_hold':
        return place_hold(
            db, x['hold_id'], x['flow'], x['case_id'], x['agency'],
            x['judge_scope'], x['issued_at'], x['expires_at'],
            x.get('supersedes'))
    if op == 'release_hold':
        return release_hold(db, x['hold_id'], x['at'], x['warrant_id'])
    if op == 'seal':
        custodian = JudicialCustodian(x['custodian_root'])
        return seal_for_court(
            db, custodian, x['seal_id'], x['handoff_id'], x['flow'],
            x['warrant_id'], x['case_id'], x['agency'], x['at'])
    if op == 'destroy':
        custodian = JudicialCustodian(x['custodian_root'])
        return execute_destruction(
            db, x['order_id'], custodian, x['at'], tuple(x.get('backup_paths', ())))
    if op == 'crypto_separate':
        custodian = JudicialCustodian(x['custodian_root'])
        return execute_crypto_separation(
            db, x['order_id'], custodian, x['at'], tuple(x.get('backup_paths', ())))
    if op == 'snapshot_backup':
        return snapshot_backup(db, x['backup_id'], x['path'], x['at'])
    return {'decision': 'unknown_operation'}
