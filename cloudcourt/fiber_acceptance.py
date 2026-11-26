"""Physical acceptance for the two protection optical routes.

The provisional activation in :mod:`cloudcourt.circuit_activation` only compares
route IDs.  Real acceptance must point every piece of evidence -- purchase
order, duct wayleave, field core labels, dual-end OTDR traces, splice-box
witness and live load tests -- at one *physical* in-service fiber core.
Different carrier names or jacket colours never prove physical separation.

Two contractually accepted delivery paths exist:

* ``permanent`` -- two physically diverse lit routes after a customer-witnessed
  short-window cut test; the install fee is then earned.
* ``temporary`` -- the existing lit route plus a wireless protection link with
  its own frequency licence and field connectivity receipt, billed as a dated
  service while the permanent build remains an open obligation.

A route that only exists on paper (``lit = 0``) can never occupy a protection
slot, and acceptance never transfers ownership or wayleave: it only records a
service state plus separate settlement entries.
"""

import json

SCHEMA = '''
CREATE TABLE IF NOT EXISTS route_cores(
    route_id TEXT, core_id TEXT, lit INTEGER, state TEXT,
    PRIMARY KEY(route_id, core_id)
);
CREATE TABLE IF NOT EXISTS route_ducts(
    route_id TEXT, duct TEXT, basis TEXT, basis_ref TEXT,
    PRIMARY KEY(route_id, duct)
);
CREATE TABLE IF NOT EXISTS splice_boxes(
    box_id TEXT PRIMARY KEY, original_label TEXT, current_label TEXT,
    location TEXT
);
CREATE TABLE IF NOT EXISTS splice_box_history(
    seq INTEGER PRIMARY KEY AUTOINCREMENT, box_id TEXT, old_label TEXT,
    new_label TEXT, notice_ref TEXT
);
CREATE TABLE IF NOT EXISTS route_boxes(
    route_id TEXT, box_id TEXT, core_id TEXT, witness_ref TEXT,
    PRIMARY KEY(route_id, box_id, core_id)
);
CREATE TABLE IF NOT EXISTS otdr_traces(
    id TEXT PRIMARY KEY, route_id TEXT, core_id TEXT, end TEXT,
    window_id TEXT, reflection_distance REAL, drawing_route TEXT,
    state TEXT DEFAULT 'recorded'
);
CREATE TABLE IF NOT EXISTS route_evidence(
    route_id TEXT, evidence_type TEXT, window_id TEXT, ref TEXT,
    core_id TEXT, state TEXT, measured REAL,
    PRIMARY KEY(route_id, evidence_type, window_id)
);
CREATE TABLE IF NOT EXISTS acceptance_windows(
    id TEXT PRIMARY KEY, tenant TEXT, capacity_required INTEGER,
    max_loss REAL, max_switchover_ms INTEGER, probe_required INTEGER,
    started_at INTEGER, closed_at INTEGER
);
CREATE TABLE IF NOT EXISTS cut_tests(
    id TEXT PRIMARY KEY, activation_id TEXT, route_id TEXT, window_id TEXT,
    customer_consent_ref TEXT, scheduled_at INTEGER, switchover_ms INTEGER,
    result TEXT
);
CREATE TABLE IF NOT EXISTS wireless_links(
    id TEXT PRIMARY KEY, tenant TEXT, licence_ref TEXT, licence_expires INTEGER,
    receipt_ref TEXT, capacity INTEGER, latency_ms INTEGER, state TEXT
);
CREATE TABLE IF NOT EXISTS temporary_protection(
    id TEXT PRIMARY KEY, activation_id TEXT, wireless_id TEXT,
    activated_at INTEGER, deactivated_at INTEGER, state TEXT
);
CREATE TABLE IF NOT EXISTS fiber_acceptance(
    activation_id TEXT PRIMARY KEY, tenant TEXT, first_route TEXT,
    second_route TEXT, state TEXT, medium TEXT, window_id TEXT,
    reasons TEXT, decided_at INTEGER
);
CREATE TABLE IF NOT EXISTS install_fees(
    activation_id TEXT PRIMARY KEY, tenant TEXT, amount INTEGER,
    collected_at INTEGER, earned_at INTEGER, acceptance_id TEXT
);
CREATE TABLE IF NOT EXISTS settlement_entries(
    id TEXT PRIMARY KEY, activation_id TEXT, kind TEXT, amount INTEGER,
    at INTEGER, note TEXT
);
'''

PURCHASE_ORDER = 'purchase_order'
WAYLEAVE = 'wayleave'
FIELD_LABEL = 'field_label'
BOX_WITNESS = 'box_witness'
LOAD_TEST = 'load_test'
ATTENUATION = 'attenuation'
PROBE = 'resolver_probe'

WINDOWED_EVIDENCE = (LOAD_TEST, ATTENUATION, PROBE)
# The resolver probe is produced by the witnessed cut test itself, so it is
# judged in the cut-test block rather than as pre-test paperwork.
MANDATORY_EVIDENCE = (PURCHASE_ORDER, WAYLEAVE, FIELD_LABEL, BOX_WITNESS,
                      LOAD_TEST, ATTENUATION)
INFO_REASONS = frozenset((
    'shared_duct',
    'duct_registry_conflict',
    'relabel_without_customer_notice',
    'drawings_conflict_with_traces',
))
# Reflections within this many metres at the same end count as the same
# physical event; OTDR distance resolution is coarser than field tape measures.
REFLECTION_TOLERANCE_M = 5.0


def _init(db):
    db.executescript(SCHEMA)


def _table_exists(db, name):
    return db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def _dedupe(items):
    seen, out = set(), []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def register_core(db, route_id, core_id, lit=1, state='in_service'):
    """Bind a physical fiber core to a registered route.

    ``lit = 0`` marks a planned/spare core that carries no light; it can be
    tested empty but can never prove the in-service core's path.
    """
    _init(db)
    db.execute('INSERT OR REPLACE INTO route_cores VALUES(?,?,?,?)',
               (route_id, core_id, 1 if lit else 0, state))
    return {'decision': 'core_registered', 'route_id': route_id,
            'core_id': core_id, 'lit': 1 if lit else 0}


def record_duct(db, route_id, duct, basis, basis_ref):
    """Append a duct occupancy entry; history is never overwritten.

    The duct registry changed coordinate datum once, so both old and new
    registrations must stay available for the review.
    """
    _init(db)
    db.execute('INSERT OR REPLACE INTO route_ducts VALUES(?,?,?,?)',
               (route_id, duct, basis, basis_ref))
    return {'decision': 'duct_recorded', 'route_id': route_id, 'duct': duct,
            'basis': basis}


def register_box(db, box_id, original_label, current_label, location):
    _init(db)
    db.execute('INSERT OR REPLACE INTO splice_boxes VALUES(?,?,?,?)',
               (box_id, original_label, current_label, location))
    return {'decision': 'box_registered', 'box_id': box_id}


def relabel_box(db, box_id, new_label, notice_ref=None):
    """Relabel a splice box, keeping the old label and any notice reference."""
    _init(db)
    row = db.execute('SELECT * FROM splice_boxes WHERE box_id=?',
                     (box_id,)).fetchone()
    if not row:
        return {'decision': 'unknown_box'}
    old_label = row['current_label']
    db.execute('UPDATE splice_boxes SET current_label=? WHERE box_id=?',
               (new_label, box_id))
    db.execute('INSERT INTO splice_box_history(box_id,old_label,new_label,notice_ref)'
               ' VALUES(?,?,?,?)', (box_id, old_label, new_label, notice_ref))
    decision = 'box_relabeled' if notice_ref else 'box_relabeled_without_notice'
    return {'decision': decision, 'box_id': box_id,
            'old_label': old_label, 'new_label': new_label}


def attach_route_box(db, route_id, box_id, core_id, witness_ref=None):
    """Record which physical core passes through which box.

    A ``witness_ref`` makes this an independent in-service witness; without it
    the binding is just an unverified registration.
    """
    _init(db)
    db.execute('INSERT OR REPLACE INTO route_boxes VALUES(?,?,?,?)',
               (route_id, box_id, core_id, witness_ref))
    return {'decision': 'route_box_attached', 'route_id': route_id,
            'box_id': box_id, 'core_id': core_id,
            'witnessed': bool(witness_ref)}


def record_trace(db, trace_id, route_id, core_id, end, window_id,
                 reflection_distance, drawing_route):
    """Store one end of a dual-end OTDR curve, including what the drawing says."""
    _init(db)
    if end not in ('A', 'B'):
        return {'decision': 'invalid_trace_end'}
    db.execute('INSERT INTO otdr_traces VALUES(?,?,?,?,?,?,?,?)',
               (trace_id, route_id, core_id, end, window_id,
                reflection_distance, drawing_route, 'recorded'))
    return {'decision': 'trace_recorded', 'trace_id': trace_id,
            'route_id': route_id, 'end': end}


def record_evidence(db, route_id, evidence_type, window_id, ref,
                    core_id=None, state='valid', measured=None):
    """File one piece of the evidence bundle for a route.

    Windowed measurements (load, attenuation, resolver probe) must name the
    acceptance window they were measured in; ``measured`` carries the value
    observed in that same window (capacity, loss...).
    """
    _init(db)
    if evidence_type not in MANDATORY_EVIDENCE:
        return {'decision': 'unknown_evidence_type'}
    if evidence_type in WINDOWED_EVIDENCE and not window_id:
        return {'decision': 'window_required'}
    db.execute('INSERT OR REPLACE INTO route_evidence VALUES(?,?,?,?,?,?,?)',
               (route_id, evidence_type, window_id, ref, core_id, state,
                measured))
    return {'decision': 'evidence_recorded', 'route_id': route_id,
            'evidence_type': evidence_type, 'state': state}


def open_window(db, window_id, tenant, capacity_required, max_loss,
                max_switchover_ms, probe_required=1, started_at=0,
                closed_at=None):
    _init(db)
    db.execute('INSERT INTO acceptance_windows VALUES(?,?,?,?,?,?,?,?)',
               (window_id, tenant, capacity_required, max_loss,
                max_switchover_ms, probe_required, started_at, closed_at))
    return {'decision': 'window_open', 'window_id': window_id}


def schedule_cut_test(db, test_id, activation_id, route_id, window_id,
                      customer_consent_ref, scheduled_at):
    """Book the contractual short-window disruptive test.

    The customer's signed consent is mandatory: cutting a live route without
    it destroys the existing service and is not an accepted test.
    """
    _init(db)
    if not customer_consent_ref:
        return {'decision': 'customer_consent_required'}
    db.execute('INSERT INTO cut_tests(id,activation_id,route_id,window_id,'
               'customer_consent_ref,scheduled_at,switchover_ms,result)'
               ' VALUES(?,?,?,?,?,?,?,?)',
               (test_id, activation_id, route_id, window_id,
                customer_consent_ref, scheduled_at, None, 'scheduled'))
    return {'decision': 'cut_test_scheduled', 'test_id': test_id}


def record_cut_result(db, test_id, switchover_ms, result, probe_ok=True):
    _init(db)
    row = db.execute('SELECT * FROM cut_tests WHERE id=?',
                     (test_id,)).fetchone()
    if not row:
        return {'decision': 'unknown_cut_test'}
    if result not in ('passed', 'failed'):
        return {'decision': 'invalid_cut_result'}
    db.execute('UPDATE cut_tests SET switchover_ms=?,result=? WHERE id=?',
               (switchover_ms, result, test_id))
    # The resolver probe is part of the same acceptance window.
    db.execute('INSERT OR REPLACE INTO route_evidence VALUES(?,?,?,?,?,?,?)',
               (row['route_id'], PROBE, row['window_id'],
               'cut-%s' % test_id, None,
               'valid' if probe_ok and result == 'passed' else 'failed', None))
    return {'decision': 'cut_result_recorded', 'test_id': test_id,
            'result': result, 'switchover_ms': switchover_ms}


def register_wireless(db, link_id, tenant, licence_ref, licence_expires,
                      receipt_ref, capacity, latency_ms, at, state='active'):
    """Register temporary wireless protection.

    A valid independent frequency licence (not expired at ``at``) and a field
    connectivity receipt are both required for the link to exist.
    """
    _init(db)
    if not licence_ref:
        return {'decision': 'frequency_licence_required'}
    if not receipt_ref:
        return {'decision': 'connectivity_receipt_required'}
    if licence_expires <= at:
        state = 'licence_expired'
    db.execute('INSERT INTO wireless_links VALUES(?,?,?,?,?,?,?,?)',
               (link_id, tenant, licence_ref, licence_expires, receipt_ref,
                capacity, latency_ms, state))
    decision = ('wireless_registered' if state == 'active'
                else 'wireless_licence_expired')
    return {'decision': decision, 'link_id': link_id, 'state': state}


def activate_temporary(db, protection_id, activation_id, wireless_id, at):
    """Turn on temporary protection; it never fills a permanent route slot."""
    _init(db)
    link = db.execute('SELECT * FROM wireless_links WHERE id=?',
                      (wireless_id,)).fetchone()
    if not link:
        return {'decision': 'unknown_wireless_link'}
    if link['state'] != 'active' or link['licence_expires'] <= at:
        return {'decision': 'temporary_protection_unavailable'}
    db.execute('INSERT INTO temporary_protection VALUES(?,?,?,?,?,?)',
               (protection_id, activation_id, wireless_id, at, None,
                'active'))
    return {'decision': 'temporary_protection_active',
            'protection_id': protection_id}


def deactivate_temporary(db, protection_id, at):
    _init(db)
    row = db.execute('SELECT * FROM temporary_protection WHERE id=?',
                     (protection_id,)).fetchone()
    if not row:
        return {'decision': 'unknown_temporary_protection'}
    db.execute('UPDATE temporary_protection SET deactivated_at=?,state=? '
               'WHERE id=?', (at, 'deactivated', protection_id))
    return {'decision': 'temporary_protection_deactivated',
            'protection_id': protection_id}


def protection_state(db, activation_id, at):
    """What the customer actually has at time ``at``.

    There is no "wireless OR north route" credit: the customer is protected
    only by a medium that is delivered and valid at this instant.  During a
    cut test with no wireless backup the answer is ``none``.
    """
    _init(db)
    acc = db.execute('SELECT * FROM fiber_acceptance WHERE activation_id=?',
                     (activation_id,)).fetchone()
    if acc and acc['state'] == 'permanent_accepted':
        return {'state': 'permanent_dual_fiber', 'medium': 'fiber',
                'activation_id': activation_id}
    row = db.execute(
        "SELECT tp.*, wl.licence_expires FROM temporary_protection tp "
        "JOIN wireless_links wl ON wl.id=tp.wireless_id "
        "WHERE tp.activation_id=? AND tp.state='active' "
        "AND wl.state='active' AND wl.licence_expires>?",
        (activation_id, at)).fetchone()
    if row:
        return {'state': 'temporary_wireless', 'medium': 'wireless',
                'activation_id': activation_id}
    return {'state': 'none', 'medium': None, 'activation_id': activation_id}


def collect_install_fee(db, activation_id, tenant, amount, collected_at):
    """Book an install fee already paid by the customer."""
    _init(db)
    db.execute('INSERT OR REPLACE INTO install_fees VALUES(?,?,?,?,?,?)',
               (activation_id, tenant, amount, collected_at, None, None))
    return {'decision': 'install_fee_collected',
            'activation_id': activation_id, 'amount': amount}


def settlement_report(db, activation_id):
    """Three separately settled buckets; acceptance is not a title deed."""
    _init(db)
    fee = db.execute('SELECT * FROM install_fees WHERE activation_id=?',
                     (activation_id,)).fetchone()
    acc = db.execute('SELECT * FROM fiber_acceptance WHERE activation_id=?',
                     (activation_id,)).fetchone()
    entries = [dict(r) for r in db.execute(
        'SELECT * FROM settlement_entries WHERE activation_id=? ORDER BY at,id',
        (activation_id,))]
    temp = [dict(r) for r in db.execute(
        'SELECT * FROM temporary_protection WHERE activation_id=?',
        (activation_id,))]
    return {
        'activation_id': activation_id,
        'install_fee': dict(fee) if fee else None,
        'install_fee_earned': bool(fee and fee['earned_at'] is not None),
        'acceptance_state': acc['state'] if acc else 'not_accepted',
        'temporary_services': temp,
        'entries': entries,
        # Signing for a service conveys neither fiber ownership nor wayleave.
        'conveys_ownership': False,
        'conveys_wayleave': False,
    }


def evaluate(db, activation_id, window_id, at, max_reflection_gap=REFLECTION_TOLERANCE_M):
    """Run the full physical acceptance and persist the verdict."""
    _init(db)
    reasons = []

    if not _table_exists(db, 'circuit_activations'):
        return _persist(db, activation_id, None, None, None, window_id, at,
                        ['activation_not_registered'], 'rejected')
    activation = db.execute(
        'SELECT * FROM circuit_activations WHERE id=?',
        (activation_id,)).fetchone()
    if not activation:
        return _persist(db, activation_id, None, None, None, window_id, at,
                        ['activation_not_registered'], 'rejected')

    tenant = activation['tenant']
    first_id, second_id = activation['first_route'], activation['second_route']
    if not _table_exists(db, 'fiber_routes'):
        return _persist(db, activation_id, tenant, first_id, second_id,
                        window_id, at, ['route_registry_missing'], 'rejected')
    window = db.execute('SELECT * FROM acceptance_windows WHERE id=?',
                        (window_id,)).fetchone()
    if not window or window['tenant'] != tenant:
        return _persist(db, activation_id, tenant, first_id, second_id,
                        window_id, at, ['acceptance_window_missing'], 'rejected')

    routes = []
    for route_id in (first_id, second_id):
        route = db.execute('SELECT * FROM fiber_routes WHERE id=?',
                           (route_id,)).fetchone()
        if not route:
            reasons.append('route_%s_missing' % route_id)
        else:
            routes.append(dict(route))
    if len(routes) != 2:
        return _persist(db, activation_id, tenant, first_id, second_id,
                        window_id, at, reasons, 'rejected')
    r1, r2 = routes[0], routes[1]

    # Different carrier names / colours are explicitly not evidence; both
    # routes must be checked against their own physical evidence bundles.
    for route in routes:
        reasons.extend(_route_reasons(db, route, window_id))
    reasons.extend(_diversity_reasons(db, r1, r2, window_id, max_reflection_gap))
    reasons = _dedupe(reasons)

    hard = [r for r in reasons if r not in INFO_REASONS]
    cut = db.execute(
        "SELECT * FROM cut_tests WHERE activation_id=? AND window_id=? "
        "ORDER BY scheduled_at DESC, id DESC LIMIT 1",
        (activation_id, window_id)).fetchone()
    if not cut:
        hard = _dedupe(hard + ['witnessed_cut_test_missing'])
    elif cut['result'] == 'scheduled':
        hard = _dedupe(hard + ['witnessed_cut_test_pending'])
    else:
        if cut['result'] != 'passed':
            hard = _dedupe(hard + ['cut_test_failed'])
        if cut['switchover_ms'] is None or cut['switchover_ms'] > window['max_switchover_ms']:
            hard = _dedupe(hard + ['switchover_over_limit'])
        probe = db.execute(
            "SELECT * FROM route_evidence WHERE route_id=? AND evidence_type=? "
            "AND window_id=?", (cut['route_id'], PROBE, window_id)).fetchone()
        if not probe or probe['state'] != 'valid':
            hard = _dedupe(hard + ['resolver_probe_failed'])

    if hard:
        pending_only = set(hard) <= {'witnessed_cut_test_pending',
                                     'witnessed_cut_test_missing'}
        state = ('evidence_complete_pending_witness' if pending_only
                 else 'rejected')
        return _persist(db, activation_id, tenant, first_id, second_id,
                        window_id, at, reasons + hard, state)

    state = 'permanent_accepted'
    _settle_permanent(db, activation_id, tenant, at)
    return _persist(db, activation_id, tenant, first_id, second_id,
                    window_id, at, reasons, state, medium='fiber')


def _active_core(db, route_id):
    row = db.execute(
        "SELECT core_id FROM route_cores WHERE route_id=? AND lit=1 "
        "AND state='in_service' ORDER BY core_id LIMIT 1", (route_id,)).fetchone()
    return row['core_id'] if row else None


def _route_reasons(db, route, window_id):
    route_id = route['id']
    out = []
    active_core = _active_core(db, route_id)
    if not active_core:
        # No lit in-service core: a planned route cannot take a protection slot.
        out.append('route_not_lit')

    for evidence_type in MANDATORY_EVIDENCE:
        if evidence_type in WINDOWED_EVIDENCE:
            row = db.execute(
                "SELECT * FROM route_evidence WHERE route_id=? AND evidence_type=? "
                "AND window_id=?", (route_id, evidence_type, window_id)).fetchone()
            if not row:
                # A measurement taken in an older/different window cannot be
                # reused: every metric must be measured in this window.
                if db.execute(
                        "SELECT 1 FROM route_evidence WHERE route_id=? AND evidence_type=?",
                        (route_id, evidence_type)).fetchone():
                    out.append('measurement_not_same_window:%s' % evidence_type)
                else:
                    out.append('evidence_missing:%s' % evidence_type)
                continue
        else:
            row = db.execute(
                "SELECT * FROM route_evidence WHERE route_id=? AND evidence_type=? "
                "ORDER BY window_id DESC LIMIT 1", (route_id, evidence_type)).fetchone()
        if not row:
            out.append('evidence_missing:%s' % evidence_type)
            continue
        if row['state'] != 'valid':
            out.append('evidence_invalid:%s' % evidence_type)
        # Spare-core evidence must not be presented for the in-service core.
        if row['core_id'] and active_core and row['core_id'] != active_core:
            out.append('evidence_core_mismatch:%s' % evidence_type)

    window = db.execute('SELECT * FROM acceptance_windows WHERE id=?',
                        (window_id,)).fetchone()
    if window:
        load = db.execute(
            "SELECT * FROM route_evidence WHERE route_id=? AND evidence_type=? "
            "AND window_id=?", (route_id, LOAD_TEST, window_id)).fetchone()
        if load and load['state'] == 'valid' and load['measured'] is not None \
                and load['measured'] < window['capacity_required']:
            out.append('capacity_below_contract')
        loss = db.execute(
            "SELECT * FROM route_evidence WHERE route_id=? AND evidence_type=? "
            "AND window_id=?", (route_id, ATTENUATION, window_id)).fetchone()
        if loss and loss['state'] == 'valid' and loss['measured'] is not None \
                and loss['measured'] > window['max_loss']:
            out.append('attenuation_over_limit')

    traces = {t['end']: t for t in db.execute(
        'SELECT * FROM otdr_traces WHERE route_id=? AND window_id=?',
        (route_id, window_id)).fetchall()}
    for end in ('A', 'B'):
        trace = traces.get(end)
        if not trace:
            out.append('otdr_trace_missing:end_%s' % end)
        elif active_core and trace['core_id'] != active_core:
            out.append('otdr_core_mismatch:end_%s' % end)
        elif trace['drawing_route'] and trace['drawing_route'] != route_id:
            out.append('drawings_conflict_with_traces')

    if active_core:
        box_rows = db.execute(
            'SELECT * FROM route_boxes WHERE route_id=?',
            (route_id,)).fetchall()
        active_boxes = [b for b in box_rows if b['core_id'] == active_core]
        if not active_boxes:
            # Bindings exist only for spare/other cores: the empty-core test
            # cannot prove where the in-service core actually goes.
            out.append('in_service_witness_missing')
        elif not any(b['witness_ref'] for b in active_boxes):
            out.append('in_service_witness_missing')

    wayleave = db.execute(
        "SELECT * FROM route_evidence WHERE route_id=? AND evidence_type=? "
        "ORDER BY window_id DESC LIMIT 1", (route_id, WAYLEAVE)).fetchone()
    if not wayleave:
        out.append('evidence_missing:wayleave')
    elif wayleave['state'] != 'valid':
        out.append('wayleave_expired')
    return out


def _box_id_for_label(db, label):
    row = db.execute(
        'SELECT box_id FROM splice_boxes WHERE current_label=? OR original_label=?',
        (label, label)).fetchone()
    return row['box_id'] if row else None


def _diversity_reasons(db, r1, r2, window_id, tolerance):
    out = []
    # Duct fields alone neither prove nor disprove diversity, but a shared
    # current duct is a finding that physical evidence must overcome.
    if r1['duct'] and r1['duct'] == r2['duct']:
        out.append('shared_duct')

    ducts1 = {d['duct'] for d in db.execute(
        'SELECT duct FROM route_ducts WHERE route_id=?', (r1['id'],)).fetchall()}
    ducts2 = {d['duct'] for d in db.execute(
        'SELECT duct FROM route_ducts WHERE route_id=?', (r2['id'],)).fetchall()}
    if ducts1 and ducts2 and ducts1 & ducts2:
        out.append('duct_registry_conflict')

    def physical_boxes(route_id, core_id):
        if not core_id:
            return set()
        return {b['box_id'] for b in db.execute(
            'SELECT box_id FROM route_boxes WHERE route_id=? AND core_id=?',
            (route_id, core_id)).fetchall()}

    c1, c2 = _active_core(db, r1['id']), _active_core(db, r2['id'])
    shared = physical_boxes(r1['id'], c1) & physical_boxes(r2['id'], c2)
    # Supplier documents may name a box by a re-stuck label.  Resolve both the
    # duct-table text and the relabeled boxes to stable physical identities:
    # identical text, or two labels landing on the same box_id, mean one box.
    label_ids = []
    for label in (r1['splice_box'], r2['splice_box']):
        if not label:
            continue
        resolved = _box_id_for_label(db, label)
        if resolved:
            label_ids.append(resolved)
    if len(set(label_ids)) < len(label_ids) or (
            r1['splice_box'] and r1['splice_box'] == r2['splice_box']):
        shared.update(label_ids)
        shared.add('label:%s' % r1['splice_box'])
    if shared:
        out.append('shared_splice_box')
        for box_id in shared:
            if not str(box_id).startswith('label:'):
                history = db.execute(
                    'SELECT 1 FROM splice_box_history WHERE box_id=? AND notice_ref IS NULL',
                    (box_id,)).fetchone()
                if history:
                    out.append('relabel_without_customer_notice')

    # Dual-end OTDR: reflections at the same distance from the same end on
    # both routes are the same physical splice event.
    for end in ('A', 'B'):
        t1 = db.execute(
            'SELECT * FROM otdr_traces WHERE route_id=? AND window_id=? AND end=?',
            (r1['id'], window_id, end)).fetchall()
        t2 = db.execute(
            'SELECT * FROM otdr_traces WHERE route_id=? AND window_id=? AND end=?',
            (r2['id'], window_id, end)).fetchall()
        for a in t1:
            for b in t2:
                if (a['reflection_distance'] is not None and
                        b['reflection_distance'] is not None and
                        abs(a['reflection_distance'] - b['reflection_distance']) <= tolerance):
                    out.append('otdr_shared_reflection:end_%s' % end)
    return _dedupe(out)


def _settle_permanent(db, activation_id, tenant, at):
    fee = db.execute('SELECT * FROM install_fees WHERE activation_id=?',
                     (activation_id,)).fetchone()
    if fee and fee['earned_at'] is None:
        db.execute('UPDATE install_fees SET earned_at=?,acceptance_id=? '
                   'WHERE activation_id=?', (at, activation_id, activation_id))
        db.execute('INSERT OR REPLACE INTO settlement_entries VALUES(?,?,?,?,?,?)',
                   ('fee-%s' % activation_id, activation_id,
                    'permanent_install_fee', fee['amount'], at,
                    'earned on permanent acceptance'))


def _persist(db, activation_id, tenant, first_route, second_route, window_id,
             at, reasons, state, medium=None):
    _init(db)
    db.execute('INSERT OR REPLACE INTO fiber_acceptance VALUES(?,?,?,?,?,?,?,?,?)',
               (activation_id, tenant, first_route, second_route, state,
                medium, window_id, json.dumps(_dedupe(reasons), ensure_ascii=False), at))
    return {'decision': state, 'activation_id': activation_id,
            'state': state, 'medium': medium,
            'reasons': _dedupe(reasons)}


_OPS = {
    'register_core': lambda db, x: register_core(
        db, x['route_id'], x['core_id'], x.get('lit', 1),
        x.get('state', 'in_service')),
    'record_duct': lambda db, x: record_duct(
        db, x['route_id'], x['duct'], x['basis'], x['basis_ref']),
    'register_box': lambda db, x: register_box(
        db, x['box_id'], x['original_label'], x['current_label'], x['location']),
    'relabel_box': lambda db, x: relabel_box(
        db, x['box_id'], x['new_label'], x.get('notice_ref')),
    'attach_route_box': lambda db, x: attach_route_box(
        db, x['route_id'], x['box_id'], x['core_id'], x.get('witness_ref')),
    'record_trace': lambda db, x: record_trace(
        db, x['id'], x['route_id'], x['core_id'], x['end'], x['window_id'],
        x['reflection_distance'], x['drawing_route']),
    'record_evidence': lambda db, x: record_evidence(
        db, x['route_id'], x['evidence_type'], x.get('window_id'), x['ref'],
        x.get('core_id'), x.get('state', 'valid'), x.get('measured')),
    'open_window': lambda db, x: open_window(
        db, x['id'], x['tenant'], x['capacity_required'], x['max_loss'],
        x['max_switchover_ms'], x.get('probe_required', 1),
        x.get('started_at', 0), x.get('closed_at')),
    'schedule_cut_test': lambda db, x: schedule_cut_test(
        db, x['id'], x['activation_id'], x['route_id'], x['window_id'],
        x['customer_consent_ref'], x['scheduled_at']),
    'record_cut_result': lambda db, x: record_cut_result(
        db, x['id'], x['switchover_ms'], x['result'], x.get('probe_ok', True)),
    'register_wireless': lambda db, x: register_wireless(
        db, x['id'], x['tenant'], x['licence_ref'], x['licence_expires'],
        x['receipt_ref'], x['capacity'], x['latency_ms'], x['at'],
        x.get('state', 'active')),
    'activate_temporary': lambda db, x: activate_temporary(
        db, x['id'], x['activation_id'], x['wireless_id'], x['at']),
    'deactivate_temporary': lambda db, x: deactivate_temporary(
        db, x['id'], x['at']),
    'collect_install_fee': lambda db, x: collect_install_fee(
        db, x['activation_id'], x['tenant'], x['amount'], x['collected_at']),
    'evaluate': lambda db, x: evaluate(
        db, x['activation_id'], x['window_id'], x['at']),
}


def run(db, x):
    """Thin command dispatcher mirroring the style of the other subsystems."""
    handler = _OPS.get(x['op'])
    if not handler:
        return {'decision': 'unknown_operation'}
    return handler(db, x)
