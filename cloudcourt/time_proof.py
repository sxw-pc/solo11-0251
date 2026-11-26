"""Verifiable interval time proofs bound to reference-source evidence.

Every reference source is registered with its physical time-distribution
chain, common upstream, observation moment, trusted calibration,
transport delay bounds and uncertainty. Sources sharing an upstream (two
antennas on one splitter) collapse to a single piece of evidence, so a
spoofed shared upstream cannot win by majority vote.

Proofs carry issuer, event digest, a verifiable interval, a per-site
sequence and a public revocation status. When uncertainty grows the
interval honestly widens; millisecond precision is never faked.
Corrections chain a new proof to the old one without rewriting signed
content, and revocation completes only after every holder of the old
version has acknowledged the notice. While the satellite source is lost
the oscillator's conservative drift bound keeps wide-interval proofs
available; narrow proofs resume only after an independent ground link
has completed round-trip calibration. Event order is decided from
intervals alone, never from receive order.
"""
import hashlib
import json
import math

from . import clock_reference, time_attestation
from .store import act, one, many

SCHEMA = clock_reference.SCHEMA + time_attestation.SCHEMA + '''
CREATE TABLE IF NOT EXISTS reference_evidence(
    id TEXT PRIMARY KEY, site TEXT, chain TEXT, upstream TEXT, antenna TEXT,
    timescale TEXT, direct INTEGER, observed_local INTEGER, offset_ms INTEGER,
    uncertainty_ms INTEGER, calibration TEXT, calibration_uncertainty_ms INTEGER,
    drift_ppm REAL, transport TEXT, total_uncertainty_ms INTEGER,
    expires INTEGER, state TEXT
);
CREATE TABLE IF NOT EXISTS leap_tables(
    id TEXT PRIMARY KEY, from_timescale TEXT, to_timescale TEXT,
    shift_ms INTEGER, effective_local INTEGER
);
CREATE TABLE IF NOT EXISTS time_proofs(
    id TEXT PRIMARY KEY, site TEXT, issuer TEXT, event_ref TEXT, event_digest TEXT,
    seq INTEGER, local_ms INTEGER, lower_ms INTEGER, upper_ms INTEGER,
    service TEXT, basis TEXT, corrects TEXT, superseded_by TEXT, revocation TEXT
);
CREATE TABLE IF NOT EXISTS proof_deliveries(
    id TEXT PRIMARY KEY, proof TEXT, recipient TEXT, kind TEXT,
    sent_at INTEGER, acked_at INTEGER, state TEXT
);
'''

PROOF_TIMESCALE = 'UTC'
OSCILLATOR_CHAIN = 'local-ocxo'
DEVICE_LINK_CHAIN = 'device-link'


def _evidence(db, evidence_id):
    return one(db, 'SELECT * FROM reference_evidence WHERE id=?', (evidence_id,))


def _valid_transport(transport):
    return (isinstance(transport, dict)
            and isinstance(transport.get('min_ms'), int)
            and isinstance(transport.get('max_ms'), int)
            and 0 <= transport['min_ms'] <= transport['max_ms'])


def _transport_half(transport):
    return (transport['max_ms'] - transport['min_ms'] + 1) // 2


def _project(hop, t_lo, t_hi):
    """Conservative true-time interval of a local-time range under one hop."""
    span = max(abs(t_lo - hop['observed_local']), abs(t_hi - hop['observed_local']))
    half = math.ceil(hop['total_uncertainty_ms'] + hop['drift_ppm'] * span)
    return t_lo + hop['offset_ms'] - half, t_hi + hop['offset_ms'] + half


def _hop(e):
    return {'evidence': e['id'], 'chain': e['chain'], 'upstream': e['upstream'],
            'offset_ms': e['offset_ms'], 'total_uncertainty_ms': e['total_uncertainty_ms'],
            'drift_ppm': e['drift_ppm'], 'observed_local': e['observed_local'],
            'timescale': e['timescale'], 'calibration': e['calibration'],
            'transport': json.loads(e['transport']) if e['transport'] else None,
            'leap_table': None, 'leap_shift_ms': 0}


def _leap(db, timescale, t):
    return one(db, '''SELECT * FROM leap_tables
                      WHERE from_timescale=? AND to_timescale=? AND effective_local<=?
                      ORDER BY effective_local DESC LIMIT 1''',
               (timescale, PROOF_TIMESCALE, t))


def _merge(db, site, t_lo, t_hi):
    """Merge verified site evidence into one true-time interval.

    Returns (lo, hi, basis_groups, error). Evidence sharing an upstream is
    one group and counts once; groups must intersect or the merge refuses
    instead of voting. Device links never act as site sources.
    """
    rows = many(db, "SELECT * FROM reference_evidence WHERE site=? AND state='verified' ORDER BY id",
                (site,))
    rows = [r for r in rows if r['chain'] != DEVICE_LINK_CHAIN
            and (not r['expires'] or t_hi <= r['expires'])]
    groups = {}
    for r in rows:
        groups.setdefault(r['upstream'], []).append(r)
    basis_groups, intervals = [], {}
    for upstream in sorted(groups):
        g_lo = g_hi = None
        hops = []
        for member in groups[upstream]:
            lo, hi = _project(member, t_lo, t_hi)
            hop = _hop(member)
            if member['timescale'] != PROOF_TIMESCALE:
                leap = _leap(db, member['timescale'], t_hi)
                if not leap:
                    return None, None, None, {'decision': 'leap_evidence_missing',
                                              'timescale': member['timescale'],
                                              'upstream': upstream}
                lo -= leap['shift_ms']
                hi -= leap['shift_ms']
                hop['leap_table'] = leap['id']
                hop['leap_shift_ms'] = leap['shift_ms']
            hops.append(hop)
            g_lo = lo if g_lo is None else max(g_lo, lo)
            g_hi = hi if g_hi is None else min(g_hi, hi)
        if g_lo > g_hi:
            return None, None, None, {'decision': 'source_conflict',
                                      'detail': 'inconsistent_upstream',
                                      'upstream': upstream}
        basis_groups.append(hops)
        intervals[upstream] = (g_lo, g_hi)
    if not intervals:
        return None, None, None, {'decision': 'no_time_evidence'}
    lo = max(v[0] for v in intervals.values())
    hi = min(v[1] for v in intervals.values())
    if lo > hi:
        return None, None, None, {'decision': 'source_conflict',
                                  'intervals': {k: list(v) for k, v in intervals.items()}}
    return lo, hi, basis_groups, None


def _chain_ids(db, proof_id):
    p = one(db, 'SELECT * FROM time_proofs WHERE id=?', (proof_id,))
    while p and p['corrects']:
        p = one(db, 'SELECT * FROM time_proofs WHERE id=?', (p['corrects'],))
    ids = []
    while p:
        ids.append(p['id'])
        p = one(db, 'SELECT * FROM time_proofs WHERE id=?', (p['superseded_by'],)) \
            if p['superseded_by'] else None
    return ids


def _chain_recipients(db, proof_id):
    ids = _chain_ids(db, proof_id)
    marks = ','.join('?' * len(ids))
    rows = many(db, f'SELECT DISTINCT recipient FROM proof_deliveries WHERE proof IN ({marks})', ids)
    return sorted(r['recipient'] for r in rows)


def _event_digest(row):
    return hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()


def _register(db, x):
    transport = x.get('transport')
    uncertainty = x.get('uncertainty_ms')
    cal_u = x.get('calibration_uncertainty_ms', 0)
    drift = x.get('drift_ppm', 0.0)
    expires = x.get('expires', 0)
    if (not x.get('site') or not x.get('chain') or not x.get('upstream')
            or not x.get('calibration') or x.get('observed_local') is None
            or x.get('offset_ms') is None
            or uncertainty is None or uncertainty < 0 or cal_u < 0 or drift < 0
            or (expires and expires <= x['observed_local'])):
        return {'decision': 'invalid_evidence'}
    if transport is not None and not _valid_transport(transport):
        return {'decision': 'invalid_transport'}
    direct = 1 if x.get('direct') else 0
    state = 'verified' if (direct or transport) else 'candidate'
    total = uncertainty + cal_u + (_transport_half(transport) if transport else 0)
    db.execute('INSERT INTO reference_evidence VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (x['id'], x['site'], x['chain'], x['upstream'], x.get('antenna', ''),
                x.get('timescale', PROOF_TIMESCALE), direct, x['observed_local'],
                x['offset_ms'], uncertainty, x['calibration'], cal_u, drift,
                json.dumps(transport, sort_keys=True) if transport else None,
                total, expires, state))
    return {'decision': 'evidence_registered', 'id': x['id'], 'state': state,
            'total_uncertainty_ms': total}


def _calibrate(db, x):
    e = _evidence(db, x.get('id'))
    if not e:
        return {'decision': 'unknown_evidence'}
    if e['state'] != 'candidate':
        return {'decision': 'not_calibratable', 'state': e['state']}
    transport = x.get('transport')
    if not _valid_transport(transport):
        return {'decision': 'invalid_transport'}
    total = e['uncertainty_ms'] + e['calibration_uncertainty_ms'] + _transport_half(transport)
    db.execute("UPDATE reference_evidence SET transport=?,total_uncertainty_ms=?,state='verified' WHERE id=?",
               (json.dumps(transport, sort_keys=True), total, e['id']))
    return {'decision': 'link_verified', 'id': e['id'], 'total_uncertainty_ms': total}


def _distrust(db, x):
    if x.get('upstream'):
        rows = many(db, "SELECT id FROM reference_evidence WHERE upstream=? AND state='verified'",
                    (x['upstream'],))
        for r in rows:
            db.execute("UPDATE reference_evidence SET state='distrusted' WHERE id=?", (r['id'],))
        return {'decision': 'upstream_distrusted', 'upstream': x['upstream'], 'count': len(rows)}
    e = _evidence(db, x.get('id'))
    if not e:
        return {'decision': 'unknown_evidence'}
    if e['state'] == 'distrusted':
        return {'decision': 'already_distrusted'}
    db.execute("UPDATE reference_evidence SET state='distrusted' WHERE id=?", (e['id'],))
    return {'decision': 'evidence_distrusted', 'id': e['id']}


def _leap_register(db, x):
    if (not x.get('from_timescale') or x.get('shift_ms') is None
            or x.get('effective_local') is None):
        return {'decision': 'invalid_leap_table'}
    db.execute('INSERT INTO leap_tables VALUES(?,?,?,?,?)',
               (x['id'], x['from_timescale'], PROOF_TIMESCALE, x['shift_ms'], x['effective_local']))
    return {'decision': 'leap_table_registered', 'id': x['id']}


def _issue(db, x):
    if not x.get('issuer'):
        return {'decision': 'missing_issuer'}
    corrects = x.get('corrects')
    head = None
    if corrects:
        head = one(db, 'SELECT * FROM time_proofs WHERE id=?', (corrects,))
        if not head:
            return {'decision': 'unknown_correction_target'}
        if head['superseded_by']:
            return {'decision': 'already_superseded', 'head': head['superseded_by']}
        root = head
        while root['corrects']:
            root = one(db, 'SELECT * FROM time_proofs WHERE id=?', (root['corrects'],))
        site = root['site']
        event_ref, event_digest = root['event_ref'], root['event_digest']
        local_ms = root['local_ms']
        root_basis = json.loads(root['basis'])
        via_id = root_basis['via']['evidence'] if root_basis.get('via') else None
    else:
        site = x.get('site')
        if not site:
            return {'decision': 'missing_site'}
        event_ref = x.get('event_ref')
        if event_ref:
            row = one(db, 'SELECT * FROM time_attestations WHERE id=?', (event_ref,))
            if not row:
                return {'decision': 'unknown_event'}
            event_digest = _event_digest(row)
        else:
            event_digest = x.get('event_digest')
            if not event_digest:
                return {'decision': 'missing_event'}
        local_ms = x.get('local_ms')
        if local_ms is None:
            return {'decision': 'missing_event_time'}
        via_id = x.get('via')
    t_lo = t_hi = local_ms
    via_hop = None
    if via_id:
        via = _evidence(db, via_id)
        if not via:
            return {'decision': 'unknown_evidence'}
        if via['state'] != 'verified':
            return {'decision': 'via_unverified', 'evidence': via_id}
        t_lo, t_hi = _project(via, local_ms, local_ms)
        via_hop = _hop(via)
    lo, hi, groups, err = _merge(db, site, t_lo, t_hi)
    if err:
        return err
    if corrects and lo == head['lower_ms'] and hi == head['upper_ms']:
        return {'decision': 'redundant_correction', 'head': head['id']}
    seq = (one(db, 'SELECT MAX(seq) s FROM time_proofs WHERE site=?', (site,))['s'] or 0) + 1
    external = any(h['chain'] != OSCILLATOR_CHAIN for g in groups for h in g)
    service = 'narrow' if external else 'wide'
    basis = json.dumps({'via': via_hop, 'groups': groups, 'proof_timescale': PROOF_TIMESCALE},
                       sort_keys=True)
    db.execute('INSERT INTO time_proofs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
               (x['id'], site, x['issuer'], event_ref, event_digest, seq, local_ms, lo, hi,
                service, basis, corrects, None, 'none'))
    if corrects:
        db.execute('UPDATE time_proofs SET superseded_by=? WHERE id=?', (x['id'], head['id']))
        for recipient in _chain_recipients(db, head['id']):
            db.execute('INSERT INTO proof_deliveries VALUES(?,?,?,?,?,?,?)',
                       (f"{x['id']}:{recipient}", x['id'], recipient, 'correction',
                        x.get('at'), None, 'sent'))
    return {'decision': 'proof_issued' if service == 'narrow' else 'proof_issued_wide',
            'id': x['id'], 'seq': seq, 'lower_ms': lo, 'upper_ms': hi,
            'service': service, 'uncertainty_ms': (hi - lo) / 2}


def _deliver(db, x):
    p = one(db, 'SELECT * FROM time_proofs WHERE id=?', (x.get('proof'),))
    if not p:
        return {'decision': 'unknown_proof'}
    if not x.get('recipient'):
        return {'decision': 'missing_recipient'}
    basis = json.loads(p['basis'])
    hops = ([basis['via']] if basis.get('via') else []) + [h for g in basis['groups'] for h in g]
    blocked = []
    for h in hops:
        e = _evidence(db, h['evidence'])
        if not e or e['state'] != 'verified':
            blocked.append(h['evidence'])
    if blocked:
        return {'decision': 'release_blocked', 'evidence': blocked}
    kind = x.get('kind', 'original')
    if p['superseded_by'] and kind == 'original':
        return {'decision': 'stale_version', 'head': p['superseded_by']}
    if one(db, 'SELECT 1 s FROM proof_deliveries WHERE proof=? AND recipient=?',
           (p['id'], x['recipient'])):
        return {'decision': 'already_delivered'}
    db.execute('INSERT INTO proof_deliveries VALUES(?,?,?,?,?,?,?)',
               (x['id'], p['id'], x['recipient'], kind, x.get('at'), None, 'sent'))
    return {'decision': 'delivered', 'id': x['id']}


def _ack(db, x):
    d = one(db, 'SELECT * FROM proof_deliveries WHERE id=?', (x.get('id'),))
    if not d:
        return {'decision': 'unknown_delivery'}
    if d['state'] == 'acked':
        return {'decision': 'already_acked'}
    db.execute("UPDATE proof_deliveries SET state='acked',acked_at=? WHERE id=?",
               (x.get('at'), d['id']))
    if d['kind'] == 'revocation':
        pending = one(db, """SELECT COUNT(*) n FROM proof_deliveries
                             WHERE proof=? AND kind='revocation' AND state!='acked'""",
                      (d['proof'],))['n']
        if not pending:
            db.execute("UPDATE time_proofs SET revocation='acked' WHERE id=?", (d['proof'],))
    return {'decision': 'delivery_acked', 'id': d['id']}


def _revoke(db, x):
    p = one(db, 'SELECT * FROM time_proofs WHERE id=?', (x.get('id'),))
    if not p:
        return {'decision': 'unknown_proof'}
    if p['revocation'] != 'none':
        return {'decision': 'already_revoked', 'revocation': p['revocation']}
    recipients = [r['recipient'] for r in
                  many(db, 'SELECT DISTINCT recipient FROM proof_deliveries WHERE proof=? ORDER BY recipient',
                       (p['id'],))]
    for recipient in recipients:
        db.execute('INSERT INTO proof_deliveries VALUES(?,?,?,?,?,?,?)',
                   (f"rev:{p['id']}:{recipient}", p['id'], recipient, 'revocation',
                    x.get('at'), None, 'sent'))
    state = 'pending' if recipients else 'acked'
    db.execute('UPDATE time_proofs SET revocation=? WHERE id=?', (state, p['id']))
    return {'decision': 'revocation_started', 'id': p['id'],
            'recipients': recipients, 'revocation': state}


def handle(db, x):
    op = x['op']
    if op == 'evidence':
        return _register(db, x)
    if op == 'calibrate':
        return _calibrate(db, x)
    if op == 'distrust':
        return _distrust(db, x)
    if op == 'leap':
        return _leap_register(db, x)
    if op == 'issue':
        return _issue(db, x)
    if op == 'deliver':
        return _deliver(db, x)
    if op == 'ack':
        return _ack(db, x)
    if op == 'revoke':
        return _revoke(db, x)
    return {'decision': 'unknown_operation'}


def run(db, x):
    return act(db, 'time_proof', x, handle)


# ---- read-side queries: customer-verifiable status, ordering, service level ----

def evidence_groups(db, site):
    """Verified evidence collapsed by common upstream: one group, one vote."""
    rows = many(db, "SELECT id,upstream FROM reference_evidence WHERE site=? AND state='verified' ORDER BY id",
                (site,))
    groups = {}
    for r in rows:
        groups.setdefault(r['upstream'], []).append(r['id'])
    return groups


def proof_status(db, proof_id):
    """Every version of a proof chain and exactly who received which one."""
    ids = _chain_ids(db, proof_id)
    if not ids:
        return None
    versions = []
    for pid in ids:
        p = one(db, 'SELECT * FROM time_proofs WHERE id=?', (pid,))
        deliveries = many(db, '''SELECT recipient,kind,state,sent_at,acked_at
                                 FROM proof_deliveries WHERE proof=? ORDER BY recipient,kind''',
                          (pid,))
        versions.append({'id': pid, 'seq': p['seq'], 'lower_ms': p['lower_ms'],
                         'upper_ms': p['upper_ms'], 'service': p['service'],
                         'superseded_by': p['superseded_by'], 'revocation': p['revocation'],
                         'deliveries': deliveries})
    return {'chain': ids, 'versions': versions}


def pending_deliveries(db):
    """Notices dispatched but not yet acknowledged (e.g. an offline witness)."""
    return many(db, """SELECT id,proof,recipient,kind,sent_at FROM proof_deliveries
                       WHERE state!='acked' ORDER BY id""")


def order(db, a, b):
    """Event order from intervals alone; receive order is never consulted."""
    pa = one(db, 'SELECT * FROM time_proofs WHERE id=?', (a,))
    pb = one(db, 'SELECT * FROM time_proofs WHERE id=?', (b,))
    if not pa or not pb:
        return {'order': 'unknown_proof'}
    if pa['upper_ms'] < pb['lower_ms']:
        return {'order': 'a-before-b'}
    if pb['upper_ms'] < pa['lower_ms']:
        return {'order': 'b-before-a'}
    return {'order': 'indeterminate'}


def service_level(db, site, at):
    """Service levels during source loss, derived from evidence, not a mode flag.

    Wide holdover proofs ride the oscillator's conservative drift bound and
    stay available while sources are gone; narrow proofs require verified
    external evidence (a ground link whose round-trip calibration finished).
    Both may be available at once.
    """
    rows = many(db, "SELECT * FROM reference_evidence WHERE site=? AND state='verified' AND chain!=?",
                (site, DEVICE_LINK_CHAIN))
    ocxo = [r for r in rows if r['chain'] == OSCILLATOR_CHAIN]
    wide = {'available': False}
    if ocxo:
        unc = min(math.ceil(r['total_uncertainty_ms'] + r['drift_ppm'] * abs(at - r['observed_local']))
                  for r in ocxo)
        wide = {'available': True, 'uncertainty_ms': unc}
    lo, hi, groups, err = _merge(db, site, at, at)
    if err:
        narrow = {'available': False, 'reason': err['decision']}
    elif any(h['chain'] != OSCILLATOR_CHAIN for g in groups for h in g):
        narrow = {'available': True, 'uncertainty_ms': (hi - lo) / 2}
    else:
        narrow = {'available': False, 'reason': 'no_external_source'}
    if not narrow['available'] and narrow.get('reason') == 'no_external_source':
        if one(db, "SELECT 1 s FROM reference_evidence WHERE site=? AND state='candidate' AND chain!=?",
               (site, DEVICE_LINK_CHAIN)):
            narrow['reason'] = 'calibration_pending'
    return {'wide': wide, 'narrow': narrow}


def verify(db, proof_id):
    """Independent customer verification of a proof against public evidence.

    Recomputes the interval from the proof's own basis snapshot, cross-checks
    the snapshot against the evidence ledger, validates the event digest and
    reports supersession / revocation / current basis trust alongside.
    """
    p = one(db, 'SELECT * FROM time_proofs WHERE id=?', (proof_id,))
    if not p:
        return {'valid': False, 'reasons': ['unknown_proof']}
    reasons = []
    basis = json.loads(p['basis'])
    if not p['issuer']:
        reasons.append('missing_issuer')
    if not p['event_digest']:
        reasons.append('missing_digest')
    if p['seq'] < 1:
        reasons.append('bad_sequence')
    if p['lower_ms'] > p['upper_ms']:
        reasons.append('inverted_interval')
    hops = ([basis['via']] if basis.get('via') else []) + [h for g in basis['groups'] for h in g]
    basis_states = {}
    for h in hops:
        e = _evidence(db, h['evidence'])
        basis_states[h['evidence']] = e['state'] if e else 'missing'
        if not e:
            reasons.append('basis_evidence_missing')
            continue
        for field in ('offset_ms', 'total_uncertainty_ms', 'drift_ppm', 'observed_local',
                      'timescale', 'calibration', 'chain', 'upstream'):
            if e[field] != h[field]:
                reasons.append('basis_tampered')
                break
        else:
            transport = json.loads(e['transport']) if e['transport'] else None
            if transport != h['transport']:
                reasons.append('basis_tampered')
    t_lo = t_hi = p['local_ms']
    if basis.get('via'):
        t_lo, t_hi = _project(basis['via'], t_lo, t_hi)
    lo = hi = None
    for group in basis['groups']:
        g_lo = g_hi = None
        for h in group:
            h_lo, h_hi = _project(h, t_lo, t_hi)
            if h['timescale'] != PROOF_TIMESCALE:
                if not h.get('leap_table'):
                    reasons.append('leap_evidence_missing')
                    continue
                leap = one(db, 'SELECT * FROM leap_tables WHERE id=?', (h['leap_table'],))
                if not leap or leap['shift_ms'] != h['leap_shift_ms']:
                    reasons.append('leap_table_mismatch')
                h_lo -= h['leap_shift_ms']
                h_hi -= h['leap_shift_ms']
            g_lo = h_lo if g_lo is None else max(g_lo, h_lo)
            g_hi = h_hi if g_hi is None else min(g_hi, h_hi)
        if g_lo is not None:
            lo = g_lo if lo is None else max(lo, g_lo)
            hi = g_hi if hi is None else min(hi, g_hi)
    if lo is not None and (lo != p['lower_ms'] or hi != p['upper_ms']):
        reasons.append('interval_mismatch')
    if p['event_ref']:
        row = one(db, 'SELECT * FROM time_attestations WHERE id=?', (p['event_ref'],))
        if not row:
            reasons.append('event_unavailable')
        elif _event_digest(row) != p['event_digest']:
            reasons.append('digest_mismatch')
    return {'valid': not reasons, 'reasons': sorted(set(reasons)),
            'status': {'superseded_by': p['superseded_by'], 'revocation': p['revocation'],
                       'basis_states': basis_states}}
