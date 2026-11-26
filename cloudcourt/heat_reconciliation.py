"""Reconciled waste-heat delivery, customer bills and post-invoice corrections.

The shared main-pipe meter only measures what the plant exported; it cannot by
itself prove how much heat either adjacent buyer actually received.  This
module keeps the physical evidence and the money facts apart until a
contractually authorised resolution connects them:

* raw readings keep their meter-local intervals; clock offsets normalize them
  to a common timeline and the unprovable boundary slivers are kept as
  uncertain intervals instead of being silently allocated;
* each branch reading is split at rejection and calibration edges; every
  segment is classified as provable delivery, disputed heat (with its physical
  reason: buyer rejection, expired calibration, backfilled reading, clock
  boundary, meter over-reading) or plant-side loss;
* the calibrated main-pipe export is a hard cap on every customer-facing kwh,
  chiller self-use heat is never billable, and no unknown value is ever pushed
  into a customer balance;
* the two contract performance modes (joint retest as the final basis, or a
  capped provisional settlement with money held in escrow pending late
  recalibration) are recorded with their authorisation and evidence, and bills
  already delivered are never rewritten -- late certificates can only create
  corrections, refunds and make-up debits that reference the original bills
  and the irreversible payments against them.
"""

import json

from .store import act, one, many

BASIS_FULL = 10000  # correction factor basis points: 10000 == 1.0

SCHEMA = '''
CREATE TABLE IF NOT EXISTS heat_branches(
    meter TEXT PRIMARY KEY, site TEXT, buyer TEXT, installed_at INTEGER,
    removed_at INTEGER, state TEXT
);
CREATE TABLE IF NOT EXISTS meter_clock_offsets(
    id TEXT PRIMARY KEY, meter TEXT, offset_seconds INTEGER, observed_at INTEGER,
    applies_from INTEGER, applies_to INTEGER
);
CREATE TABLE IF NOT EXISTS reading_provenance(
    reading TEXT PRIMARY KEY, origin TEXT, recorded_at INTEGER
);
CREATE TABLE IF NOT EXISTS calibration_certificates(
    id TEXT PRIMARY KEY, meter TEXT, valid_from INTEGER, valid_until INTEGER,
    issued_at INTEGER, correction_factor INTEGER, evidence TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS heat_readings(
    id TEXT PRIMARY KEY, meter TEXT, site TEXT, kind TEXT, raw_start INTEGER,
    raw_end INTEGER, start_at INTEGER, end_at INTEGER, kwh INTEGER,
    calibration TEXT
);
CREATE TABLE IF NOT EXISTS heat_temperature_records(
    id TEXT PRIMARY KEY, meter TEXT, at INTEGER, inlet INTEGER, outlet INTEGER,
    calibration TEXT
);
CREATE TABLE IF NOT EXISTS heat_rejection_notices(
    id TEXT PRIMARY KEY, site TEXT, buyer TEXT, start_at INTEGER,
    end_at INTEGER, notified_at INTEGER
);
CREATE TABLE IF NOT EXISTS heat_contracts(
    id TEXT PRIMARY KEY, site TEXT, buyer TEXT, minimum_kwh INTEGER,
    base_rate INTEGER, over_rate INTEGER, shortfall_rate INTEGER,
    reject_delta INTEGER
);
CREATE TABLE IF NOT EXISTS heat_periods(
    id TEXT PRIMARY KEY, site TEXT, start_at INTEGER, end_at INTEGER,
    export_kwh INTEGER, self_use_kwh INTEGER, pipe_loss_kwh INTEGER,
    excluded_kwh INTEGER, legacy_overbilled_kwh INTEGER, state TEXT
);
CREATE TABLE IF NOT EXISTS heat_allocations(
    id TEXT PRIMARY KEY, period TEXT, buyer TEXT, provable_kwh INTEGER,
    disputed_kwh INTEGER, provisional_kwh INTEGER, certified_kwh INTEGER,
    final_kwh INTEGER, state TEXT
);
CREATE TABLE IF NOT EXISTS heat_uncertain_intervals(
    id TEXT PRIMARY KEY, period TEXT, meter TEXT, buyer TEXT,
    start_at INTEGER, end_at INTEGER, kwh INTEGER, reason TEXT,
    evidence TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS heat_resolutions(
    id TEXT PRIMARY KEY, period TEXT, mode TEXT, authorized_by TEXT,
    authorized_at INTEGER, basis TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS heat_invoices(
    id TEXT PRIMARY KEY, site TEXT, buyer TEXT, start_at INTEGER,
    end_at INTEGER, billed_kwh INTEGER, state TEXT
);
CREATE TABLE IF NOT EXISTS heat_bills(
    id TEXT PRIMARY KEY, period TEXT, buyer TEXT, kind TEXT, kwh INTEGER,
    amount INTEGER, basis TEXT, state TEXT, created_at INTEGER
);
CREATE TABLE IF NOT EXISTS heat_payments(
    id TEXT PRIMARY KEY, bill TEXT, buyer TEXT, amount INTEGER, paid_at INTEGER,
    state TEXT
);
CREATE TABLE IF NOT EXISTS heat_escrow(
    id TEXT PRIMARY KEY, period TEXT, buyer TEXT, bill TEXT, amount INTEGER,
    state TEXT
);
CREATE TABLE IF NOT EXISTS heat_refunds(
    id TEXT PRIMARY KEY, payment TEXT, bill TEXT, buyer TEXT, amount INTEGER,
    kind TEXT, basis TEXT, state TEXT, created_at INTEGER
);
CREATE TABLE IF NOT EXISTS heat_retests(
    id TEXT PRIMARY KEY, period TEXT, buyer TEXT, kwh INTEGER, at INTEGER,
    agreed_by TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS recalibration_certificates(
    id TEXT PRIMARY KEY, meter TEXT, issued_at INTEGER, covers_from INTEGER,
    covers_to INTEGER, correction_factor INTEGER, evidence TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS heat_ledger_entries(
    id TEXT PRIMARY KEY, period TEXT, buyer TEXT, direction TEXT,
    amount INTEGER, ref_type TEXT, ref_id TEXT, at INTEGER, basis TEXT
);
'''

# When branch readings over-claim the calibrated export, the least trustworthy
# evidence is trimmed first; a validly measured segment is never trimmed.
TRIM_ORDER = ('calibration_expired', 'backfilled_reading', 'buyer_rejection')


def ensure_schema(db):
    db.executescript(SCHEMA)


def _ensure(db):
    ensure_schema(db)


def _clock_offset(db, meter, at):
    row = one(db, '''SELECT offset_seconds FROM meter_clock_offsets
                     WHERE meter=? AND applies_from<=? AND applies_to>?
                     ORDER BY applies_from DESC LIMIT 1''', (meter, at, at))
    return row['offset_seconds'] if row else 0


def _calibration_valid(db, cert_id, start_at, end_at):
    cert = one(db, 'SELECT * FROM calibration_certificates WHERE id=?',
               (cert_id,))
    return bool(cert and cert['state'] == 'active'
                and cert['valid_from'] <= start_at
                and cert['valid_until'] >= end_at)


def _clip(kwh, ts, te, start, end):
    """Clip a reading to the period edge; integer kwh stays traceable."""
    if ts >= start and te <= end:
        return kwh, ts, te, 0, ts, te
    total = te - ts
    cs, ce = max(ts, start), min(te, end)
    inside = kwh * (ce - cs) // total
    return (inside, cs, ce, kwh - inside,
            ts if ts < start else ce, te if te > end else cs)


def _segment_reason(db, site, meter, reading_id, calibration, buyer, s, e):
    contract = one(db, 'SELECT * FROM heat_contracts WHERE site=? AND buyer=?',
                   (site, buyer))
    notice = one(db, '''SELECT 1 FROM heat_rejection_notices
                        WHERE site=? AND buyer=? AND start_at<? AND end_at>?
                        LIMIT 1''', (site, buyer, e, s))
    breach = one(db, '''SELECT 1 FROM heat_temperature_records
                        WHERE meter=? AND at>=? AND at<? AND (inlet-outlet)<?
                        LIMIT 1''',
                 (meter, s, e, contract['reject_delta'] if contract else 0))
    if notice and breach:
        return 'buyer_rejection'
    if not _calibration_valid(db, calibration, s, e):
        return 'calibration_expired'
    prov = one(db, 'SELECT origin FROM reading_provenance WHERE reading=?',
               (reading_id,))
    if prov and prov['origin'] == 'backfill':
        return 'backfilled_reading'
    return None


def _split_segments(db, reading, buyer, cs, ce, kwh):
    """Split one reading at rejection / calibration edges, prorating kwh."""
    site, meter = reading['site'], reading['meter']
    edges = {cs, ce}
    for n in many(db, '''SELECT * FROM heat_rejection_notices
                         WHERE site=? AND buyer=? AND start_at<? AND end_at>?''',
                  (site, buyer, ce, cs)):
        edges.add(max(cs, n['start_at']))
        edges.add(min(ce, n['end_at']))
    cert = one(db, 'SELECT * FROM calibration_certificates WHERE id=?',
               (reading['calibration'],))
    if cert:
        if cs < cert['valid_until'] < ce:
            edges.add(cert['valid_until'])
        if cs < cert['valid_from'] < ce:
            edges.add(cert['valid_from'])
    edges = sorted(edges)
    spans = [(edges[i], edges[i + 1]) for i in range(len(edges) - 1)
             if edges[i + 1] > edges[i]]
    total_span = ce - cs
    weights = [b - a for a, b in spans]
    allocated = [kwh * w // total_span for w in weights]
    remainder = kwh - sum(allocated)
    if remainder and weights:
        # rounding remainder goes to the widest segment, matching the
        # uniform-flow physical assumption while preserving total kwh
        biggest = max(range(len(weights)), key=lambda i: weights[i])
        allocated[biggest] += remainder
    out = []
    for (a, b), part in zip(spans, allocated):
        out.append((a, b, part,
                    _segment_reason(db, site, meter, reading['id'],
                                    reading['calibration'], buyer, a, b)))
    return out


def _ledger(db, entry_id, period, buyer, direction, amount, ref_type, ref_id,
            at, basis):
    db.execute('INSERT INTO heat_ledger_entries VALUES(?,?,?,?,?,?,?,?,?)',
               (entry_id, period, buyer, direction, amount, ref_type, ref_id,
                at, basis))


def _price(contract, kwh):
    within = min(kwh, contract['minimum_kwh'])
    over = max(0, kwh - contract['minimum_kwh'])
    return within * contract['base_rate'] + over * contract['over_rate']


def _add_uncertain(db, u_id, period, meter, buyer, s, e, kwh, reason, evidence):
    db.execute('INSERT INTO heat_uncertain_intervals VALUES(?,?,?,?,?,?,?,?,?,?)',
               (u_id, period, meter, buyer, s, e, kwh, reason,
                json.dumps(evidence, sort_keys=True), 'open'))


# --------------------------------------------------------------------------- #
# evidence intake
# --------------------------------------------------------------------------- #

def _register_branch(db, x):
    if one(db, 'SELECT 1 FROM heat_branches WHERE meter=?', (x['id'],)):
        return {'decision': 'business_identity_conflict'}
    db.execute('INSERT INTO heat_branches VALUES(?,?,?,?,?,?)',
               (x['id'], x['site'], x['buyer'], x['installed_at'], None,
                'active'))
    return {'decision': 'branch_registered'}


def _remove_meter(db, x):
    row = one(db, 'SELECT * FROM heat_branches WHERE meter=?', (x['id'],))
    if not row or row['state'] != 'active':
        return {'decision': 'meter_not_active'}
    db.execute('UPDATE heat_branches SET removed_at=?, state=? WHERE meter=?',
               (x['removed_at'], 'removed', x['id']))
    return {'decision': 'meter_removed'}


def _clock(db, x):
    db.execute('INSERT INTO meter_clock_offsets VALUES(?,?,?,?,?,?)',
               (x['id'], x['meter'], x['offset_seconds'], x['observed_at'],
                x['applies_from'], x['applies_to']))
    return {'decision': 'clock_offset_recorded'}


def _provenance(db, x):
    db.execute('INSERT INTO reading_provenance VALUES(?,?,?)',
               (x['reading'], x['origin'], x['recorded_at']))
    return {'decision': 'provenance_recorded'}


def _certificate(db, x):
    db.execute('INSERT INTO calibration_certificates VALUES(?,?,?,?,?,?,?,?)',
               (x['id'], x['meter'], x['valid_from'], x['valid_until'],
                x['issued_at'], x.get('correction_factor', BASIS_FULL),
                x.get('evidence', ''), 'active'))
    return {'decision': 'certificate_registered'}


def _temperature(db, x):
    db.execute('INSERT INTO heat_temperature_records VALUES(?,?,?,?,?,?)',
               (x['id'], x['meter'], x['at'], x['inlet'], x['outlet'],
                x['calibration']))
    return {'decision': 'temperature_recorded'}


def _rejection(db, x):
    db.execute('INSERT INTO heat_rejection_notices VALUES(?,?,?,?,?,?)',
               (x['id'], x['site'], x['buyer'], x['start_at'], x['end_at'],
                x['notified_at']))
    return {'decision': 'rejection_notice_recorded'}


def _contract(db, x):
    db.execute('INSERT INTO heat_contracts VALUES(?,?,?,?,?,?,?,?)',
               (x['id'], x['site'], x['buyer'], x['minimum_kwh'],
                x['base_rate'], x['over_rate'], x['shortfall_rate'],
                x['reject_delta']))
    return {'decision': 'contract_registered'}


def plant_reading(db, reading_id, meter, site, kind, raw_start, raw_end, kwh,
                  calibration):
    """Record a plant-side meter reading.

    The meter-local interval is preserved on ``heat_readings.raw_*``; the
    clock-normalized interval is stored there as well as in ``plant_meters``,
    whose calibrated total feeds the legacy provisional billing path.  The
    original reading and its applicable interval therefore remain auditable
    while every consumer works on the common timeline.
    """
    _ensure(db)
    from .plant_meter import reading
    offset = _clock_offset(db, meter, raw_start)
    start_at, end_at = raw_start - offset, raw_end - offset
    reading(db, reading_id, site, kind, start_at, end_at, kwh, calibration)
    db.execute('INSERT OR REPLACE INTO heat_readings VALUES(?,?,?,?,?,?,?,?,?,?)',
               (f'plant-{reading_id}', meter, site, kind, raw_start, raw_end,
                start_at, end_at, kwh, calibration))
    return {'decision': 'plant_reading_recorded',
            'start_at': start_at, 'end_at': end_at}


def _reading(db, x):
    branch = one(db, 'SELECT * FROM heat_branches WHERE meter=?', (x['meter'],))
    if not branch or branch['state'] != 'active':
        return {'decision': 'meter_not_in_service'}
    if branch['removed_at'] is not None and x['raw_start'] >= branch['removed_at']:
        return {'decision': 'meter_not_in_service'}
    offset = _clock_offset(db, x['meter'], x['raw_start'])
    db.execute('INSERT INTO heat_readings VALUES(?,?,?,?,?,?,?,?,?,?)',
               (x['id'], x['meter'], x['site'], x.get('kind', 'branch'),
                x['raw_start'], x['raw_end'], x['raw_start'] - offset,
                x['raw_end'] - offset, x['kwh'], x['calibration']))
    return {'decision': 'reading_recorded',
            'start_at': x['raw_start'] - offset,
            'end_at': x['raw_end'] - offset}


# --------------------------------------------------------------------------- #
# period reconciliation
# --------------------------------------------------------------------------- #

def _reconcile(db, x):
    period, site, start, end = x['id'], x['site'], x['start_at'], x['end_at']
    if one(db, 'SELECT 1 FROM heat_periods WHERE id=?', (period,)):
        return {'decision': 'business_identity_conflict'}
    exports = many(db, '''SELECT * FROM heat_readings
                          WHERE site=? AND kind='export'
                          AND start_at>=? AND end_at<=?''',
                   (site, start, end))
    if not exports:
        return {'decision': 'export_uncalibrated'}
    for row in exports:
        if not _calibration_valid(db, row['calibration'], row['start_at'],
                                  row['end_at']):
            return {'decision': 'export_uncalibrated'}
    export_kwh = sum(r['kwh'] for r in exports)
    chill = many(db, '''SELECT COALESCE(SUM(kwh),0) kwh FROM heat_readings
                        WHERE site=? AND kind='chiller'
                        AND start_at>=? AND end_at<=?''',
                 (site, start, end))[0]['kwh']
    electric = many(db, '''SELECT COALESCE(SUM(kwh),0) kwh FROM heat_readings
                           WHERE site=? AND kind='electric'
                           AND start_at>=? AND end_at<=?''',
                    (site, start, end))[0]['kwh']

    provable, disputed = {}, {}
    seq = 0
    rows = many(db, '''SELECT * FROM heat_readings
                       WHERE site=? AND kind='branch' ORDER BY id''', (site,))
    for r in rows:
        branch = one(db, 'SELECT * FROM heat_branches WHERE meter=?',
                     (r['meter'],))
        if not branch:
            return {'decision': 'branch_unregistered', 'meter': r['meter']}
        buyer = branch['buyer']
        ts, te = r['start_at'], r['end_at']
        if te <= start or ts >= end:
            seq += 1
            _add_uncertain(db, f'{period}-u{seq}', period, r['meter'], buyer,
                           ts, te, r['kwh'], 'clock_skew_boundary',
                           {'reading': r['id'], 'offset_seconds':
                            _clock_offset(db, r['meter'], r['raw_start'])})
            continue
        inside, cs, ce, outside, os_, oe = _clip(
            r['kwh'], ts, te, start, end)
        if outside:
            seq += 1
            _add_uncertain(db, f'{period}-u{seq}', period, r['meter'], buyer,
                           os_, oe, outside, 'clock_skew_boundary',
                           {'reading': r['id']})
        for a, b, part, reason in _split_segments(db, r, buyer, cs, ce, inside):
            if not part:
                continue
            if reason:
                disputed[buyer] = disputed.get(buyer, 0) + part
                seq += 1
                _add_uncertain(db, f'{period}-u{seq}', period, r['meter'],
                               buyer, a, b, part, reason,
                               {'reading': r['id'],
                                'calibration': r['calibration']})
            else:
                provable[buyer] = provable.get(buyer, 0) + part

    # Hard cap part 1: customer-claimable heat (provable + non-rejection
    # disputed) must never exceed the calibrated main-pipe export.
    rejected_total = sum(
        u['kwh'] for u in many(
            db, '''SELECT * FROM heat_uncertain_intervals
                   WHERE period=? AND reason='buyer_rejection' AND state='open' ''',
            (period,)))
    claimed = (sum(provable.values()) + sum(disputed.values())
               - rejected_total)
    excluded = 0

    def trim(reasons, over):
        """Downgrade the least-trustworthy open intervals as over-reading."""
        nonlocal seq, excluded
        for reason in reasons:
            if over == 0:
                break
            for u in many(db, '''SELECT * FROM heat_uncertain_intervals
                                 WHERE period=? AND reason=? AND state='open'
                                 ORDER BY id DESC''', (period, reason)):
                if over == 0:
                    break
                cut = min(over, u['kwh'])
                db.execute('UPDATE heat_uncertain_intervals SET kwh=kwh-? WHERE id=?',
                           (cut, u['id']))
                seq += 1
                _add_uncertain(db, f'{period}-u{seq}', period, u['meter'],
                               u['buyer'], u['start_at'], u['end_at'], cut,
                               'meter_over_reading',
                               {'source_interval': u['id'],
                                'export_kwh': export_kwh})
                disputed[u['buyer']] -= cut
                excluded += cut
                over -= cut
        return over

    if claimed > export_kwh:
        if trim(TRIM_ORDER, claimed - export_kwh) > 0:
            return {'decision': 'delivery_exceeds_calibrated_export'}

    # Hard cap part 2: even including the rejected tail, the branch meters
    # cannot have observed more heat than the main pipe delivered; anything
    # beyond it is meter over-reading attached to the rejecting buyer.
    total_observed = sum(provable.values()) + sum(disputed.values())
    if total_observed > export_kwh:
        if trim(('buyer_rejection',), total_observed - export_kwh) > 0:
            return {'decision': 'delivery_exceeds_calibrated_export'}

    # Energy balance: export = provable + disputed + unattributed plant-side
    # loss. Rejected heat and over-reading stay tagged with their physical
    # reason; nothing unproven is pushed into a customer balance.
    pipe_loss = max(0, export_kwh - sum(provable.values())
                    - sum(disputed.values()))
    legacy = many(db, '''SELECT COALESCE(SUM(billed_kwh),0) kwh FROM heat_invoices
                         WHERE site=? AND start_at>=? AND end_at<=?''',
                  (site, start, end))[0]['kwh']
    overbilled = max(0, legacy - export_kwh)

    db.execute('INSERT INTO heat_periods VALUES(?,?,?,?,?,?,?,?,?,?)',
               (period, site, start, end, export_kwh, chill, pipe_loss,
                excluded, overbilled, 'reconciled'))
    for buyer in sorted(set(provable) | set(disputed)):
        db.execute('INSERT INTO heat_allocations VALUES(?,?,?,?,?,?,?,?,?)',
                   (f'{period}-{buyer}', period, buyer,
                    provable.get(buyer, 0), disputed.get(buyer, 0), 0, 0, 0,
                    'reconciled'))
    return {'decision': 'reconciled', 'period': period,
            'export_kwh': export_kwh, 'self_use_kwh': chill,
            'electric_kwh': electric, 'pipe_loss_kwh': pipe_loss,
            'excluded_kwh': excluded,
            'provable_kwh': dict(sorted(provable.items())),
            'disputed_kwh': dict(sorted(disputed.items())),
            'legacy_overbilled_kwh': overbilled}


# --------------------------------------------------------------------------- #
# resolutions, bills, payments, escrow
# --------------------------------------------------------------------------- #

def _resolve(db, x):
    period = one(db, 'SELECT * FROM heat_periods WHERE id=?', (x['period'],))
    if not period or period['state'] != 'reconciled':
        return {'decision': 'period_not_reconciled'}
    if one(db, 'SELECT 1 FROM heat_resolutions WHERE period=?', (x['period'],)):
        return {'decision': 'resolution_exists'}
    if x['mode'] not in ('retest', 'provisional_capped'):
        return {'decision': 'unknown_resolution_mode'}
    allocs = many(db, 'SELECT * FROM heat_allocations WHERE period=?',
                  (x['period'],))
    at = x['authorized_at']
    db.execute('INSERT INTO heat_resolutions VALUES(?,?,?,?,?,?,?)',
               (x['id'], x['period'], x['mode'], x['authorized_by'], at,
                json.dumps({'allocations': [a['id'] for a in allocs]},
                           sort_keys=True), 'active'))
    billed = 0
    for a in allocs:
        contract = one(db, 'SELECT * FROM heat_contracts WHERE site=? AND buyer=?',
                       (period['site'], a['buyer']))
        if x['mode'] == 'retest':
            kwh, kind, escrow_part = a['provable_kwh'], 'retest_interim', 0
        else:
            rejected = many(db, '''SELECT COALESCE(SUM(kwh),0) kwh FROM
                                   heat_uncertain_intervals WHERE period=?
                                   AND buyer=? AND reason='buyer_rejection'
                                   AND state='open' ''',
                            (x['period'], a['buyer']))[0]['kwh']
            eligible = max(0, a['disputed_kwh'] - rejected)
            kwh = a['provable_kwh'] + eligible
            kind, escrow_part = 'provisional_capped', eligible
        if kwh <= 0:
            continue
        billed += kwh
        if billed > period['export_kwh']:
            return {'decision': 'export_cap_breach'}
        amount = _price(contract, kwh)
        bill_id = f'{x["period"]}-{a["buyer"]}-{kind}'
        db.execute('INSERT INTO heat_bills VALUES(?,?,?,?,?,?,?,?,?)',
                   (bill_id, x['period'], a['buyer'], kind, kwh, amount,
                    json.dumps({'allocation': a['id']}, sort_keys=True),
                    'issued', at))
        _ledger(db, f'{bill_id}-ledger', x['period'], a['buyer'], 'debit',
                amount, 'bill', bill_id, at, x['mode'])
        db.execute('UPDATE heat_allocations SET provisional_kwh=?, state=? WHERE id=?',
                   (kwh, 'billed', a['id']))
        if escrow_part:
            escrow_amount = amount - _price(contract, a['provable_kwh'])
            db.execute('INSERT INTO heat_escrow VALUES(?,?,?,?,?,?)',
                       (f'{bill_id}-escrow', x['period'], a['buyer'], bill_id,
                        escrow_amount, 'held'))
            _ledger(db, f'{bill_id}-escrow-ledger', x['period'], a['buyer'],
                    'escrow_hold', escrow_amount, 'escrow', bill_id, at,
                    'disputed portion pending recalibration')
    return {'decision': 'resolution_adopted', 'mode': x['mode'],
            'billed_kwh': billed}


def _pay(db, x):
    bill = one(db, 'SELECT * FROM heat_bills WHERE id=?', (x['bill'],))
    if not bill or bill['state'] not in ('issued', 'provisional', 'interim'):
        return {'decision': 'bill_not_payable'}
    if x['amount'] != bill['amount']:
        return {'decision': 'payment_amount_mismatch'}
    db.execute('INSERT INTO heat_payments VALUES(?,?,?,?,?,?)',
               (x['id'], bill['id'], bill['buyer'], x['amount'], x['at'],
                'paid'))
    db.execute("UPDATE heat_bills SET state='paid' WHERE id=?", (bill['id'],))
    _ledger(db, f'{x["id"]}-ledger', bill['period'], bill['buyer'],
            'credit_payment', x['amount'], 'payment', x['id'], x['at'],
            f'payment for {bill["id"]}')
    return {'decision': 'payment_received'}


def _bounce(db, x):
    payment = one(db, 'SELECT * FROM heat_payments WHERE id=?', (x['id'],))
    if not payment or payment['state'] != 'paid':
        return {'decision': 'payment_not_reversible'}
    bill = one(db, 'SELECT * FROM heat_bills WHERE id=?', (payment['bill'],))
    db.execute("UPDATE heat_payments SET state='reversed' WHERE id=?",
               (x['id'],))
    db.execute("UPDATE heat_bills SET state='issued' WHERE id=?",
               (payment['bill'],))
    db.execute("UPDATE heat_escrow SET state='returned' WHERE bill=?",
               (payment['bill'],))
    _ledger(db, f'{x["id"]}-bounce', bill['period'], payment['buyer'],
            'reversal', payment['amount'], 'payment', x['id'], x['at'],
            'bank reversal')
    return {'decision': 'payment_reversed'}


def _refund(db, x, at=None):
    basis = x.get('basis', '')
    if not basis:
        return {'decision': 'evidence_required'}
    payment = one(db, 'SELECT * FROM heat_payments WHERE id=?',
                  (x['payment'],))
    if not payment:
        return {'decision': 'payment_unknown'}
    if payment['state'] != 'paid':
        return {'decision': 'payment_reversed' if payment['state'] == 'reversed'
                else 'payment_not_held'}
    bill = one(db, 'SELECT * FROM heat_bills WHERE id=?', (payment['bill'],))
    already = many(db, '''SELECT COALESCE(SUM(amount),0) n FROM heat_refunds
                          WHERE payment=?''', (x['payment'],))[0]['n']
    if x['amount'] <= 0 or x['amount'] > payment['amount'] - already:
        return {'decision': 'refund_exceeds_payment'}
    created = at if at is not None else x['at']
    db.execute('INSERT INTO heat_refunds VALUES(?,?,?,?,?,?,?,?,?)',
               (x['id'], payment['id'], bill['id'], bill['buyer'],
                x['amount'], x.get('kind', 'refund'), basis, 'paid_out',
                created))
    _ledger(db, f'{x["id"]}-ledger', bill['period'], bill['buyer'], 'refund',
            x['amount'], 'refund', x['id'], created, basis)
    db.execute("UPDATE heat_bills SET state='corrected' WHERE id=?",
               (bill['id'],))
    return {'decision': 'refund_issued', 'amount': x['amount']}


# --------------------------------------------------------------------------- #
# joint retest (final basis for the retest resolution)
# --------------------------------------------------------------------------- #

def _retest(db, x):
    period = one(db, 'SELECT * FROM heat_periods WHERE id=?', (x['period'],))
    resolution = one(db, 'SELECT * FROM heat_resolutions WHERE period=?',
                     (x['period'],))
    if not period or not resolution or resolution['mode'] != 'retest':
        return {'decision': 'retest_not_authorized'}
    parties = set(x['agreed_by'])
    if len(parties) != 2:
        return {'decision': 'retest_needs_joint_agreement'}
    alloc = one(db, 'SELECT * FROM heat_allocations WHERE period=? AND buyer=?',
                (x['period'], x['buyer']))
    if not alloc or alloc['final_kwh']:
        return {'decision': 'retest_not_acceptable'}
    rejected = many(db, '''SELECT COALESCE(SUM(kwh),0) kwh FROM heat_uncertain_intervals
                           WHERE period=? AND buyer=? AND reason='buyer_rejection'
                           AND state='open' ''',
                    (x['period'], x['buyer']))[0]['kwh']
    retestable = alloc['disputed_kwh'] - rejected
    if x['kwh'] < 0 or x['kwh'] > retestable:
        return {'decision': 'retest_outside_evidence'}
    # The joint retest can only confirm heat evidenced by non-rejection
    # intervals; meter over-reading and clock slivers are outside its scope.
    evidenced = many(db, '''SELECT COALESCE(SUM(kwh),0) kwh FROM heat_uncertain_intervals
                            WHERE period=? AND buyer=?
                            AND reason IN ('calibration_expired','backfilled_reading')
                            AND state='open' ''',
                     (x['period'], x['buyer']))[0]['kwh']
    if x['kwh'] > evidenced:
        return {'decision': 'retest_outside_evidence'}
    db.execute('INSERT INTO heat_retests VALUES(?,?,?,?,?,?,?)',
               (x['id'], x['period'], x['buyer'], x['kwh'], x['at'],
               json.dumps(sorted(parties)), 'agreed'))
    remaining = x['kwh']
    candidates = many(db, '''SELECT * FROM heat_uncertain_intervals
                             WHERE period=? AND buyer=?
                             AND reason IN ('calibration_expired','backfilled_reading')
                             AND state='open' ORDER BY id''',
                      (x['period'], x['buyer']))
    for u in candidates:
        if remaining <= 0:
            db.execute("UPDATE heat_uncertain_intervals SET state='written_off' WHERE id=?",
                       (u['id'],))
            continue
        confirmed = min(remaining, u['kwh'])
        if confirmed == u['kwh']:
            db.execute("UPDATE heat_uncertain_intervals SET state='retest_confirmed' WHERE id=?",
                       (u['id'],))
        else:
            db.execute("UPDATE heat_uncertain_intervals SET kwh=?, state='retest_confirmed' WHERE id=?",
                       (confirmed, u['id']))
            db.execute('INSERT INTO heat_uncertain_intervals VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (f'{u["id"]}-off', x['period'], u['meter'], u['buyer'],
                        u['start_at'], u['end_at'], u['kwh'] - confirmed,
                        u['reason'], u['evidence'], 'written_off'))
        remaining -= confirmed
    db.execute("""UPDATE heat_uncertain_intervals SET state='rejection_upheld'
                  WHERE period=? AND buyer=? AND reason='buyer_rejection'
                  AND state='open'""", (x['period'], x['buyer']))
    db.execute("""UPDATE heat_uncertain_intervals SET state='written_off'
                  WHERE period=? AND buyer=? AND reason='meter_over_reading'
                  AND state='open'""", (x['period'], x['buyer']))
    final_kwh = alloc['provable_kwh'] + x['kwh']
    db.execute('UPDATE heat_allocations SET final_kwh=?, state=? WHERE id=?',
               (final_kwh, 'finalized', alloc['id']))
    contract = one(db, 'SELECT * FROM heat_contracts WHERE site=? AND buyer=?',
                   (period['site'], x['buyer']))
    interim = one(db, '''SELECT * FROM heat_bills WHERE period=? AND buyer=?
                         AND kind='retest_interim' ''',
                  (x['period'], x['buyer']))
    final_amount = _price(contract, final_kwh)
    if interim:
        # The interim bill already settled the provable part; the final bill
        # is a net make-up so cumulative billed kwh can never exceed delivery.
        db.execute("UPDATE heat_bills SET state='superseded' WHERE id=?",
                   (interim['id'],))
        net_amount = final_amount - interim['amount']
        bill_id = f'{x["period"]}-{x["buyer"]}-retest_final'
        if net_amount > 0:
            db.execute('INSERT INTO heat_bills VALUES(?,?,?,?,?,?,?,?,?)',
                       (bill_id, x['period'], x['buyer'], 'retest_final',
                        x['kwh'], net_amount,
                        json.dumps({'retest': x['id'],
                                    'supersedes': interim['id']},
                                   sort_keys=True), 'issued', x['at']))
            _ledger(db, f'{bill_id}-ledger', x['period'], x['buyer'], 'debit',
                    net_amount, 'bill', bill_id, x['at'],
                    'joint retest net make-up on confirmed disputed heat')
    elif final_kwh:
        bill_id = f'{x["period"]}-{x["buyer"]}-retest_final'
        db.execute('INSERT INTO heat_bills VALUES(?,?,?,?,?,?,?,?,?)',
                   (bill_id, x['period'], x['buyer'], 'retest_final',
                    final_kwh, final_amount,
                    json.dumps({'retest': x['id']}, sort_keys=True), 'issued',
                    x['at']))
        _ledger(db, f'{bill_id}-ledger', x['period'], x['buyer'], 'debit',
                final_amount, 'bill', bill_id, x['at'],
                'joint retest final basis')
    comp = 0
    if final_kwh < contract['minimum_kwh']:
        comp = (contract['minimum_kwh'] - final_kwh) * contract['shortfall_rate']
        _ledger(db, f'{x["period"]}-{x["buyer"]}-comp', x['period'],
                x['buyer'], 'compensation', comp, 'contract', contract['id'],
                x['at'], 'short supply below minimum commitment')
    if not many(db, "SELECT 1 FROM heat_allocations WHERE period=? AND final_kwh=0",
                (x['period'],)):
        db.execute("UPDATE heat_resolutions SET state='finalized' WHERE period=?",
                   (x['period'],))
    return {'decision': 'retest_finalized', 'buyer': x['buyer'],
            'final_kwh': final_kwh, 'compensation': comp}


# --------------------------------------------------------------------------- #
# late recalibration: corrections only, original bills are never rewritten
# --------------------------------------------------------------------------- #

def _recalibrate(db, x):
    if not x.get('evidence'):
        return {'decision': 'evidence_required'}
    if one(db, 'SELECT 1 FROM recalibration_certificates WHERE id=?',
           (x['id'],)):
        return {'decision': 'business_identity_conflict'}
    overlap = many(db, '''SELECT * FROM recalibration_certificates WHERE meter=?
                          AND covers_from<? AND covers_to>?''',
                   (x['meter'], x['covers_to'], x['covers_from']))
    for old in overlap:
        if old['correction_factor'] == x['correction_factor']:
            return {'decision': 'certificate_already_recorded'}
    if overlap and not x.get('supersedes'):
        return {'decision': 'unsubstantiated_certificate'}
    db.execute('INSERT INTO recalibration_certificates VALUES(?,?,?,?,?,?,?,?)',
               (x['id'], x['meter'], x['issued_at'], x['covers_from'],
                x['covers_to'], x['correction_factor'], x['evidence'],
                'active'))
    period = one(db, 'SELECT * FROM heat_periods WHERE id=?', (x['period'],))
    resolution = one(db, 'SELECT * FROM heat_resolutions WHERE period=?',
                     (x['period'],))
    if not period or not resolution:
        return {'decision': 'period_not_resolved'}
    if resolution['mode'] == 'retest':
        # The jointly agreed retest is the final basis; a late certificate is
        # retained as evidence but cannot reopen delivered/paid accounts.
        return {'decision': 'cert_recorded_retest_final'}

    result = {'decision': 'recalibration_applied', 'corrections': []}
    buyers = sorted(u['buyer'] for u in many(
        db, '''SELECT DISTINCT buyer FROM heat_uncertain_intervals
               WHERE period=? AND meter=? AND reason='calibration_expired'
               AND state='open' ''', (x['period'], x['meter'])))
    for buyer in buyers:
        alloc = one(db, 'SELECT * FROM heat_allocations WHERE period=? AND buyer=?',
                    (x['period'], buyer))
        contract = one(db, 'SELECT * FROM heat_contracts WHERE site=? AND buyer=?',
                       (period['site'], buyer))
        certified = 0
        for u in many(db, '''SELECT * FROM heat_uncertain_intervals WHERE period=?
                             AND buyer=? AND meter=? AND reason='calibration_expired'
                             AND state='open' ORDER BY id''',
                      (x['period'], buyer, x['meter'])):
            fixed = u['kwh'] * x['correction_factor'] // BASIS_FULL
            certified += fixed
            db.execute("UPDATE heat_uncertain_intervals SET state='recalibrated' WHERE id=?",
                       (u['id'],))
            if fixed < u['kwh']:
                db.execute('INSERT INTO heat_uncertain_intervals VALUES(?,?,?,?,?,?,?,?,?,?)',
                           (f'{u["id"]}-loss', x['period'], u['meter'], buyer,
                            u['start_at'], u['end_at'], u['kwh'] - fixed,
                            'meter_over_reading', u['evidence'],
                            'written_off'))
        final_kwh = alloc['provable_kwh'] + certified
        other = many(db, '''SELECT COALESCE(SUM(COALESCE(final_kwh,provable_kwh)),0) kwh
                            FROM heat_allocations WHERE period=? AND buyer!=?''',
                     (x['period'], buyer))[0]['kwh']
        final_kwh = min(final_kwh, max(0, period['export_kwh'] - other))
        db.execute('UPDATE heat_allocations SET certified_kwh=?, final_kwh=?, state=? WHERE id=?',
                   (certified, final_kwh, 'finalized', alloc['id']))
        bill = one(db, '''SELECT * FROM heat_bills WHERE period=? AND buyer=?
                          AND kind='provisional_capped' ''',
                   (x['period'], buyer))
        final_amount = _price(contract, final_kwh)
        if bill and final_kwh < bill['kwh']:
            diff_amount = bill['amount'] - final_amount
            payment = one(db, '''SELECT * FROM heat_payments WHERE bill=?
                                 ORDER BY paid_at DESC LIMIT 1''', (bill['id'],))
            escrow = one(db, "SELECT * FROM heat_escrow WHERE bill=? AND state='held'",
                         (bill['id'],))
            if payment and payment['state'] == 'paid' and diff_amount > 0:
                rf = _refund(db, {'id': f'{x["period"]}-{buyer}-refund',
                                  'payment': payment['id'],
                                  'amount': diff_amount,
                                  'basis': f'recalibration:{x["id"]}',
                                  'kind': 'overcharge_refund',
                                  'at': x['issued_at']},
                             at=x['issued_at'])
                result['corrections'].append(rf)
            elif diff_amount > 0:
                _ledger(db, f'{x["period"]}-{buyer}-credit', x['period'],
                        buyer, 'refund', diff_amount, 'certificate', x['id'],
                        x['issued_at'], 'credit only: payment not held')
                result['corrections'].append(
                    {'decision': 'credit_recorded', 'amount': diff_amount})
            if escrow:
                db.execute("UPDATE heat_escrow SET state='settled' WHERE id=?",
                           (escrow['id'],))
        elif bill and final_kwh > bill['kwh']:
            debit = final_amount - bill['amount']
            make_up_id = f'{x["period"]}-{buyer}-makeup'
            db.execute('INSERT INTO heat_bills VALUES(?,?,?,?,?,?,?,?,?)',
                       (make_up_id, x['period'], buyer, 'make_up_debit',
                        final_kwh - bill['kwh'], debit,
                        json.dumps({'certificate': x['id']}, sort_keys=True),
                        'issued', x['issued_at']))
            _ledger(db, f'{make_up_id}-ledger', x['period'], buyer, 'debit',
                    debit, 'bill', make_up_id, x['issued_at'],
                    'confirmed heat after recalibration')
            escrow = one(db, "SELECT * FROM heat_escrow WHERE bill=? AND state='held'",
                         (bill['id'],))
            if escrow:
                db.execute("UPDATE heat_escrow SET state='released' WHERE id=?",
                           (escrow['id'],))
            result['corrections'].append(
                {'decision': 'make_up_debit', 'amount': debit})
        if final_kwh < contract['minimum_kwh']:
            comp = (contract['minimum_kwh'] - final_kwh) * contract['shortfall_rate']
            _ledger(db, f'{x["period"]}-{buyer}-comp', x['period'], buyer,
                    'compensation', comp, 'contract', contract['id'],
                    x['issued_at'], 'short supply below minimum commitment')
            result['corrections'].append(
                {'decision': 'shortfall_compensation', 'amount': comp})
        # legacy provisional invoices for this exact period are marked
        # corrected; bills delivered in other periods are never touched
        db.execute('''UPDATE heat_invoices SET state='corrected'
                      WHERE site=? AND buyer=? AND start_at>=? AND end_at<=?''',
                   (period['site'], buyer, period['start_at'],
                    period['end_at']))
    db.execute("UPDATE heat_resolutions SET state='finalized' WHERE period=?",
               (x['period'],))
    return result


def rebuild_accounts(db, period_id):
    """Rebuild the legitimate ledger for both contract performance modes.

    Only one mode was actually authorised for this period; the other view is
    reconstructed from the same physical evidence so both legally distinct
    accounts can be compared without reusing money facts that never happened.
    Money rows (payments, refunds, escrow) are therefore reported only under
    the mode whose resolution actually adopted them.
    """
    _ensure(db)
    period = one(db, 'SELECT * FROM heat_periods WHERE id=?', (period_id,))
    if not period:
        return {'decision': 'period_unknown'}
    resolution = one(db, 'SELECT * FROM heat_resolutions WHERE period=?',
                     (period_id,))
    actual_mode = resolution['mode'] if resolution else None
    total_billed = many(db, '''SELECT COALESCE(SUM(kwh),0) n FROM heat_bills
                               WHERE period=?''', (period_id,))[0]['n']
    views = {}
    for mode in ('retest', 'provisional_capped'):
        views[mode] = {}
        is_actual = mode == actual_mode
        for alloc in many(db, '''SELECT * FROM heat_allocations WHERE period=?
                                 ORDER BY buyer''', (period_id,)):
            buyer = alloc['buyer']
            rejected = many(db, '''SELECT COALESCE(SUM(kwh),0) kwh FROM
                                   heat_uncertain_intervals WHERE period=?
                                   AND buyer=? AND reason='buyer_rejection'
                                   AND state!='written_off' ''',
                            (period_id, buyer))[0]['kwh']
            retest_confirmed = many(db, '''SELECT COALESCE(SUM(kwh),0) kwh FROM
                                           heat_uncertain_intervals WHERE period=?
                                           AND buyer=? AND state='retest_confirmed' ''',
                                    (period_id, buyer))[0]['kwh']
            if mode == 'retest':
                # evidence-driven view: provable heat plus whatever a joint
                # retest has confirmed; rejected heat can never enter it
                final = alloc['provable_kwh'] + retest_confirmed
                status = ('finalized' if alloc['final_kwh']
                          else 'awaiting_retest')
            else:
                # capped provisional view: provable plus non-rejection
                # disputed heat, replaced by certified figures once a late
                # recalibration has substantiated them
                final = (alloc['final_kwh']
                         or alloc['provisional_kwh']
                         or alloc['provable_kwh']
                         + max(0, alloc['disputed_kwh'] - rejected))
                status = alloc['state']
            entry = {'provable_kwh': alloc['provable_kwh'],
                     'final_kwh': final, 'status': status,
                     'is_authorized_path': is_actual,
                     'paid_amount': 0, 'refunded_amount': 0,
                     'compensation_amount': 0, 'escrow_held': 0}
            if is_actual:
                entry['paid_amount'] = many(db, '''
                    SELECT COALESCE(SUM(p.amount),0) n FROM heat_payments p
                    JOIN heat_bills b ON b.id=p.bill
                    WHERE b.period=? AND b.buyer=? AND p.state='paid' ''',
                    (period_id, buyer))[0]['n']
                entry['refunded_amount'] = many(db, '''
                    SELECT COALESCE(SUM(amount),0) n FROM heat_refunds
                    WHERE buyer=? AND state='paid_out' ''', (buyer,))[0]['n']
                entry['compensation_amount'] = many(db, '''
                    SELECT COALESCE(SUM(amount),0) n FROM heat_ledger_entries
                    WHERE period=? AND buyer=? AND direction='compensation' ''',
                    (period_id, buyer))[0]['n']
                entry['escrow_held'] = many(db, '''
                    SELECT COALESCE(SUM(amount),0) n FROM heat_escrow
                    WHERE period=? AND buyer=? AND state='held' ''',
                    (period_id, buyer))[0]['n']
            views[mode][buyer] = entry
    return {'decision': 'accounts_rebuilt', 'period': period_id,
            'authorized_mode': actual_mode,
            'export_kwh': period['export_kwh'],
            'self_use_kwh': period['self_use_kwh'],
            'pipe_loss_kwh': period['pipe_loss_kwh'],
            'billable_within_export': total_billed <= period['export_kwh'],
            'views': views}


def handle(db, x):
    # Schema is ensured by store.act() before the transaction opens; running
    # DDL here would auto-commit it and destroy the business_action savepoint.
    op = x['op']
    if op == 'branch':
        return _register_branch(db, x)
    if op == 'remove_meter':
        return _remove_meter(db, x)
    if op == 'clock':
        return _clock(db, x)
    if op == 'provenance':
        return _provenance(db, x)
    if op == 'certificate':
        return _certificate(db, x)
    if op == 'temperature':
        return _temperature(db, x)
    if op == 'rejection':
        return _rejection(db, x)
    if op == 'contract':
        return _contract(db, x)
    if op == 'reading':
        return _reading(db, x)
    if op == 'reconcile':
        return _reconcile(db, x)
    if op == 'resolve':
        return _resolve(db, x)
    if op == 'pay':
        return _pay(db, x)
    if op == 'bounce':
        return _bounce(db, x)
    if op == 'refund':
        return _refund(db, x)
    if op == 'retest':
        return _retest(db, x)
    if op == 'recalibrate':
        return _recalibrate(db, x)
    return {'decision': 'unknown_operation'}


def run(db, x):
    return act(db, 'heat', x, handle)
