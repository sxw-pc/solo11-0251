import sqlite3
import unittest

from cloudcourt import heat_reconciliation as hr
from cloudcourt.heat_delivery import provisional_invoice
from cloudcourt.store import connect, replay
from cloudcourt import store

SITE = 'site-1'
START, END = 0, 600


def seed_evidence(db):
    """Insert all physical evidence for the prompt's scenario."""
    for meter, buyer in (('MA', 'buyer-A'), ('MB', 'buyer-B')):
        hr.handle(db, {'op': 'branch', 'id': meter, 'site': SITE,
                       'buyer': buyer, 'installed_at': -1000})
    hr.handle(db, {'op': 'clock', 'id': 'c-main', 'meter': 'M-main',
                   'offset_seconds': 180, 'observed_at': -10,
                   'applies_from': -1000, 'applies_to': 100000})
    hr.handle(db, {'op': 'clock', 'id': 'c-a', 'meter': 'MA',
                   'offset_seconds': 300, 'observed_at': -10,
                   'applies_from': -1000, 'applies_to': 100000})
    hr.handle(db, {'op': 'clock', 'id': 'c-b', 'meter': 'MB',
                   'offset_seconds': 300, 'observed_at': -10,
                   'applies_from': -1000, 'applies_to': 100000})
    hr.handle(db, {'op': 'certificate', 'id': 'C-export', 'meter': 'M-main',
                   'valid_from': -100, 'valid_until': 100000, 'issued_at': -100,
                   'evidence': 'seal-1'})
    hr.handle(db, {'op': 'certificate', 'id': 'C-A', 'meter': 'MA',
                   'valid_from': -100, 'valid_until': 100000, 'issued_at': -100,
                   'evidence': 'seal-2'})
    hr.handle(db, {'op': 'certificate', 'id': 'C-B', 'meter': 'MB',
                   'valid_from': -100, 'valid_until': 300, 'issued_at': -200,
                   'evidence': 'seal-3'})
    # main-pipe export: raw 180..780, clock +180 -> true 0..600, exactly 100
    hr.plant_reading(db, 'M-main', 'M-main', SITE, 'export',
                     180, 780, 100, 'C-export')
    hr.plant_reading(db, 'M-chill', 'M-chill', SITE, 'chiller',
                     0, 600, 25, 'C-export')
    hr.plant_reading(db, 'M-electric', 'M-electric', SITE, 'electric',
                     0, 600, 1000, 'C-export')
    # A: raw 300..900 (+300 -> 0..600), 61 kwh; rejects tail from true 210
    hr.handle(db, {'op': 'reading', 'id': 'r-a', 'meter': 'MA', 'site': SITE,
                   'raw_start': 300, 'raw_end': 900, 'kwh': 61,
                   'calibration': 'C-A'})
    # B: raw 300..900 (+300 -> 0..600), 48 kwh; probe expires at true 300
    hr.handle(db, {'op': 'reading', 'id': 'r-b', 'meter': 'MB', 'site': SITE,
                   'raw_start': 300, 'raw_end': 900, 'kwh': 48,
                   'calibration': 'C-B'})
    hr.handle(db, {'op': 'rejection', 'id': 'rej-a', 'site': SITE,
                   'buyer': 'buyer-A', 'start_at': 210, 'end_at': 600,
                   'notified_at': 205})
    for at in range(210, 600, 30):
        hr.handle(db, {'op': 'temperature', 'id': f't-a-{at}', 'meter': 'MA',
                       'at': at, 'inlet': 40, 'outlet': 28,
                       'calibration': 'C-A'})
    hr.handle(db, {'op': 'contract', 'id': 'K-A', 'site': SITE,
                   'buyer': 'buyer-A', 'minimum_kwh': 45, 'base_rate': 10,
                   'over_rate': 12, 'shortfall_rate': 3, 'reject_delta': 15})
    hr.handle(db, {'op': 'contract', 'id': 'K-B', 'site': SITE,
                   'buyer': 'buyer-B', 'minimum_kwh': 40, 'base_rate': 10,
                   'over_rate': 14, 'shortfall_rate': 2, 'reject_delta': 15})


def base_evidence(db, period='P1'):
    """Evidence for the prompt's scenario: export 100, A=61, B=48 raw."""
    seed_evidence(db)
    return hr.handle(db, {'op': 'reconcile', 'id': period, 'site': SITE,
                          'start_at': START, 'end_at': END})


def db():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY '
                 'AUTOINCREMENT, subsystem TEXT, command TEXT, event_id TEXT '
                 'UNIQUE, payload TEXT, result TEXT)')
    hr.ensure_schema(conn)
    return conn


def allocation(db_, period, buyer):
    return store.one(db_, 'SELECT * FROM heat_allocations WHERE period=? AND buyer=?',
                     (period, buyer))


class HeatReconciliationTest(unittest.TestCase):
    def setUp(self):
        self.db = db()

    def tearDown(self):
        self.db.close()

    def test_double_billing_is_detected_and_replaced_by_evidence_ledgers(self):
        seed_evidence(self.db)
        # the legacy provisional module bills the full shared export total to
        # each buyer, so the same 100 kwh is invoiced twice
        self.assertEqual(100, provisional_invoice(self.db, 'L1', SITE,
                                                  'buyer-A', START, END))
        self.assertEqual(100, provisional_invoice(self.db, 'L2', SITE,
                                                  'buyer-B', START, END))
        result = hr.handle(self.db, {'op': 'reconcile', 'id': 'P-legacy',
                                     'site': SITE, 'start_at': START,
                                     'end_at': END})
        self.assertEqual('reconciled', result['decision'])
        self.assertEqual(100, result['export_kwh'])
        # 200 was invoiced against a calibrated delivery of 100
        self.assertEqual(100, result['legacy_overbilled_kwh'])
        # the simple branch sum sells 109 against 100 delivered; the excess
        # 9 is rejected as meter over-reading, and no customer-facing kwh ever
        # exceeds the calibrated export
        # full energy balance. The 9 kwh of meter over-reading was already
        # deducted from buyer-A's disputed total (40 rejected -> 31 + 9
        # over-reading), so observed evidence plus plant loss closes exactly
        # at the calibrated 100 kwh export; nothing unproven reaches a buyer.
        observed = (result['provable_kwh']['buyer-A']
                    + result['provable_kwh']['buyer-B']
                    + result['disputed_kwh']['buyer-A']
                    + result['disputed_kwh']['buyer-B'])
        over = sum(u['kwh'] for u in store.many(
            self.db,
            "SELECT * FROM heat_uncertain_intervals WHERE reason='meter_over_reading'"))
        self.assertEqual(9, over)
        self.assertEqual(observed + result['pipe_loss_kwh'], 100)
        rejected = store.one(
            self.db,
            "SELECT COALESCE(SUM(kwh),0) n FROM heat_uncertain_intervals "
            "WHERE reason='buyer_rejection'")['n']
        self.assertEqual(31, rejected)
        hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P-legacy',
                            'mode': 'provisional_capped',
                            'authorized_by': 'joint', 'authorized_at': 610})
        for bill in store.many(self.db, 'SELECT * FROM heat_bills'):
            self.assertNotEqual(bill['kwh'], 100)
        self.assertTrue(hr.rebuild_accounts(self.db, 'P-legacy')
                        ['billable_within_export'])

    def test_clock_skew_normalizes_intervals_and_keeps_boundary_uncertainty(self):
        result = base_evidence(self.db)
        self.assertEqual('reconciled', result['decision'])
        normalized = store.one(self.db, 'SELECT * FROM heat_readings WHERE id=?',
                               ('r-a',))
        self.assertEqual((0, 600), (normalized['start_at'], normalized['end_at']))
        self.assertEqual((300, 900),
                         (normalized['raw_start'], normalized['raw_end']))
        # a reading shifted fully outside the period stays uncertain, never sold
        hr.handle(self.db, {'op': 'reading', 'id': 'r-out', 'meter': 'MA',
                            'site': SITE, 'raw_start': 905, 'raw_end': 960,
                            'kwh': 7, 'calibration': 'C-A'})
        out = hr.handle(self.db, {'op': 'reconcile', 'id': 'P-out',
                                  'site': SITE, 'start_at': START, 'end_at': END})
        self.assertEqual('reconciled', out['decision'])
        u = store.many(self.db,
                       "SELECT * FROM heat_uncertain_intervals WHERE period='P-out' AND reason='clock_skew_boundary'")
        self.assertEqual(7, sum(r['kwh'] for r in u))
        # in-period evidence is still reconciled; the shifted reading itself
        # never contributes to any buyer's provable balance
        shifted = store.one(self.db,
                            "SELECT * FROM heat_uncertain_intervals WHERE period='P-out' AND meter='MA' AND reason='clock_skew_boundary'")
        self.assertEqual(7, shifted['kwh'])
        self.assertEqual(21, out['provable_kwh']['buyer-A'])

    def test_expired_branch_probe_is_disputed_not_scaled_away(self):
        result = base_evidence(self.db)
        b = allocation(self.db, 'P1', 'buyer-B')
        # 48 * 300/600 = 24 provable; the expired tail (24) is disputed
        self.assertEqual(24, b['provable_kwh'])
        self.assertEqual(24, b['disputed_kwh'])
        reasons = {u['reason'] for u in store.many(
            self.db,
            "SELECT * FROM heat_uncertain_intervals WHERE period='P1' AND buyer='buyer-B'")}
        self.assertIn('calibration_expired', reasons)
        self.assertEqual(100, result['export_kwh'])

    def test_buyer_a_rejection_is_upheld_and_never_billed(self):
        base_evidence(self.db)
        a = allocation(self.db, 'P1', 'buyer-A')
        self.assertEqual(21, a['provable_kwh'])   # 61 * 210/600
        # rejected tail 61-21=40; 9 of it over-reads the calibrated export and
        # is split out as meter over-reading, leaving 31 as upheld rejection
        self.assertEqual(31, a['disputed_kwh'])
        rej = store.many(self.db,
                         "SELECT * FROM heat_uncertain_intervals WHERE period='P1' AND reason='buyer_rejection'")
        self.assertEqual(31, sum(u['kwh'] for u in rej))
        over = store.many(self.db,
                          "SELECT * FROM heat_uncertain_intervals WHERE period='P1' AND reason='meter_over_reading'")
        self.assertEqual(9, sum(u['kwh'] for u in over))
        for mode in ('retest', 'provisional_capped'):
            d = db()
            base_evidence(d)
            hr.handle(d, {'op': 'resolve', 'id': f'R-{mode}', 'period': 'P1',
                          'mode': mode, 'authorized_by': 'joint',
                          'authorized_at': 610})
            bills = store.many(d,
                               "SELECT * FROM heat_bills WHERE buyer='buyer-A'")
            self.assertTrue(all(b['kwh'] <= 21 for b in bills))
            d.close()

    def test_chiller_self_use_heat_is_never_billable(self):
        result = base_evidence(self.db)
        self.assertEqual(25, result['self_use_kwh'])
        hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P1',
                            'mode': 'provisional_capped',
                            'authorized_by': 'joint', 'authorized_at': 610})
        bills = store.many(self.db, 'SELECT * FROM heat_bills')
        self.assertTrue(bills)
        self.assertTrue(all(b['kwh'] <= 65 for b in bills))
        total = sum(b['kwh'] for b in bills)
        self.assertLessEqual(total, result['export_kwh'])
        rebuilt = hr.rebuild_accounts(self.db, 'P1')
        self.assertTrue(rebuilt['billable_within_export'])
        self.assertEqual(25, rebuilt['self_use_kwh'])

    def test_pipe_loss_is_plant_side_not_shared_revenue(self):
        result = base_evidence(self.db)
        # 100 export balances to: provable 21+24, B disputed 24, A rejected
        # 31 and 9 kwh of branch meter over-reading; no unattributed loss here
        self.assertEqual(0, result['pipe_loss_kwh'])
        loss = store.one(self.db, 'SELECT pipe_loss_kwh FROM heat_periods WHERE id=?',
                         ('P1',))
        self.assertEqual(0, loss['pipe_loss_kwh'])
        accepted = store.many(
            self.db,
            "SELECT * FROM heat_uncertain_intervals WHERE reason='buyer_rejection'")
        # rejected heat stays tagged with its physical reason, never as revenue
        self.assertTrue(all(u['state'] == 'open' for u in accepted))
        self.assertFalse(store.one(
            self.db,
            "SELECT 1 FROM heat_uncertain_intervals WHERE reason LIKE '%revenue%'"))

    def test_unattributed_pipe_loss_is_recorded_when_branches_under_read(self):
        d = db()
        base_evidence(d)
        # shrink both branch readings: the missing heat cannot be assigned to
        # either buyer and is recorded as unattributed plant-side loss
        d.execute("UPDATE heat_readings SET kwh=kwh-5 WHERE meter IN ('MA','MB')")
        out = hr.handle(d, {'op': 'reconcile', 'id': 'P-loss', 'site': SITE,
                            'start_at': START, 'end_at': END})
        self.assertEqual('reconciled', out['decision'])
        # after shrinking both branches their observed total fits the export,
        # so nothing is excluded; the single unassigned kwh is plant loss
        self.assertEqual(0, out['excluded_kwh'])
        self.assertEqual(1, out['pipe_loss_kwh'])
        d.close()

    def test_export_cap_trims_over_claiming_meter_evidence(self):
        d = db()
        # same evidence but an export meter that only delivered 90 calibrated
        base_evidence(d)
        d.execute("UPDATE heat_readings SET kwh=90 WHERE meter='M-main' AND kind='export'")
        d.execute("UPDATE plant_meters SET kwh=90 WHERE id='M-main'")
        second = hr.handle(d, {'op': 'reconcile', 'id': 'P2', 'site': SITE,
                               'start_at': START, 'end_at': END})
        self.assertEqual('reconciled', second['decision'])
        self.assertEqual(90, second['export_kwh'])
        # part 1: 45 provable + 24 B-disputed = 69 claimable > none over 90;
        # part 2: total observed 109 exceeds 90, so 19 kwh is over-reading
        self.assertEqual(19, second['excluded_kwh'])
        over = store.many(d,
                          "SELECT * FROM heat_uncertain_intervals WHERE period='P2' AND reason='meter_over_reading'")
        self.assertEqual(19, sum(u['kwh'] for u in over))
        # validly measured segments are never touched; only B's expired probe
        # and A's rejection tail absorb the trim
        self.assertEqual(21, second['provable_kwh']['buyer-A'])
        self.assertEqual(24, second['provable_kwh']['buyer-B'])
        self.assertEqual(21, second['disputed_kwh']['buyer-A'])
        self.assertEqual(24, second['disputed_kwh']['buyer-B'])
        d.close()

    def test_retest_resolution_bills_only_provable_and_finalizes_with_joint_basis(self):
        base_evidence(self.db)
        hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P1',
                            'mode': 'retest', 'authorized_by': 'joint',
                            'authorized_at': 610})
        interim = store.one(self.db,
                            "SELECT * FROM heat_bills WHERE buyer='buyer-A' AND kind='retest_interim'")
        self.assertEqual(21, interim['kwh'])
        # unilateral retest is rejected
        denied = hr.handle(self.db, {'op': 'retest', 'id': 'rt-bad',
                                     'period': 'P1', 'buyer': 'buyer-B',
                                     'kwh': 10, 'at': 700,
                                     'agreed_by': ['plant']})
        self.assertEqual('retest_needs_joint_agreement', denied['decision'])
        # retest cannot confirm more heat than the disputed evidence held
        outside = hr.handle(self.db, {'op': 'retest', 'id': 'rt-out',
                                      'period': 'P1', 'buyer': 'buyer-B',
                                      'kwh': 25, 'at': 700,
                                      'agreed_by': ['plant', 'buyer-B']})
        self.assertEqual('retest_outside_evidence', outside['decision'])
        ok = hr.handle(self.db, {'op': 'retest', 'id': 'rt-b',
                                 'period': 'P1', 'buyer': 'buyer-B',
                                 'kwh': 20, 'at': 700,
                                 'agreed_by': ['plant', 'buyer-B']})
        self.assertEqual('retest_finalized', ok['decision'])
        self.assertEqual(44, ok['final_kwh'])
        a = hr.handle(self.db, {'op': 'retest', 'id': 'rt-a',
                                'period': 'P1', 'buyer': 'buyer-A',
                                'kwh': 0, 'at': 701,
                                'agreed_by': ['plant', 'buyer-A']})
        self.assertEqual(21, a['final_kwh'])
        self.assertEqual((45 - 21) * 3, a['compensation'])  # short supply
        rejection = store.many(
            self.db,
            "SELECT * FROM heat_uncertain_intervals WHERE reason='buyer_rejection'")
        self.assertTrue(all(u['state'] == 'rejection_upheld' for u in rejection))
        rebuilt = hr.rebuild_accounts(self.db, 'P1')
        self.assertEqual(21, rebuilt['views']['retest']['buyer-A']['final_kwh'])
        self.assertEqual(44, rebuilt['views']['retest']['buyer-B']['final_kwh'])

    def test_provisional_capped_resolution_holds_escrow_and_refunds_after_recalibration(self):
        base_evidence(self.db)
        res = hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P1',
                                  'mode': 'provisional_capped',
                                  'authorized_by': 'joint',
                                  'authorized_at': 610})
        # A: 21 provable only (rejected tail is excluded), B: 24+24=48
        self.assertEqual(69, res['billed_kwh'])
        escrow = store.one(self.db,
                           "SELECT * FROM heat_escrow WHERE buyer='buyer-B' AND state='held'")
        # B's provisional bill prices 48 kwh: 40 inside the minimum at 10 and
        # 8 over-quota at 14 = 512; the provable-only bill for 24 kwh is 240,
        # so the disputed portion holds 512-240=272 in escrow
        self.assertEqual(272, escrow['amount'])
        b_bill = store.one(self.db,
                           "SELECT * FROM heat_bills WHERE buyer='buyer-B' AND kind='provisional_capped'")
        self.assertEqual(512, b_bill['amount'])
        pay = hr.handle(self.db, {'op': 'pay', 'id': 'pay-b',
                                  'bill': b_bill['id'], 'amount': 512, 'at': 620})
        self.assertEqual('payment_received', pay['decision'])
        # late recalibration: factor 9000 -> expired 24 kwh really was 21,
        # so certified final B delivery is 45 kwh (40 at 10 + 5 over at 14=470)
        recal = hr.handle(self.db, {
            'op': 'recalibrate', 'id': 'RC-B', 'meter': 'MB',
            'issued_at': 900, 'covers_from': 300, 'covers_to': 600,
            'correction_factor': 9000, 'evidence': 'lab-report-7',
            'period': 'P1'})
        self.assertEqual('recalibration_applied', recal['decision'])
        refund = store.one(self.db, "SELECT * FROM heat_refunds")
        # provisional 512 - corrected final 470 = 42, all tied to the payment
        self.assertEqual(42, refund['amount'])
        self.assertEqual('paid_out', refund['state'])
        self.assertFalse(store.one(
            self.db,
            "SELECT 1 FROM heat_escrow WHERE state='held'"))
        # original bill row survives, marked corrected rather than rewritten
        self.assertEqual('corrected', store.one(
            self.db, 'SELECT state FROM heat_bills WHERE id=?',
            (b_bill['id'],))['state'])
        rebuilt = hr.rebuild_accounts(self.db, 'P1')
        view = rebuilt['views']['provisional_capped']['buyer-B']
        self.assertEqual(45, view['final_kwh'])
        self.assertEqual(42, view['refunded_amount'])
        self.assertEqual(512, view['paid_amount'])

    def test_make_up_debit_when_recalibration_confirms_more_heat(self):
        base_evidence(self.db)
        hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P1',
                            'mode': 'provisional_capped',
                            'authorized_by': 'joint', 'authorized_at': 610})
        b_bill = store.one(self.db,
                           "SELECT * FROM heat_bills WHERE buyer='buyer-B' AND kind='provisional_capped'")
        hr.handle(self.db, {'op': 'pay', 'id': 'pay-makeup', 'bill': b_bill['id'],
                            'amount': 512, 'at': 620})
        out = hr.handle(self.db, {
            'op': 'recalibrate', 'id': 'RC-B2', 'meter': 'MB',
            'issued_at': 900, 'covers_from': 300, 'covers_to': 600,
            'correction_factor': 10500, 'evidence': 'lab-report-8',
            'period': 'P1'})
        makeup = [c for c in out['corrections'] if c['decision'] == 'make_up_debit']
        self.assertEqual(1, len(makeup))
        # 24 * 1.05 = 25 certified -> 49 final vs 48 provisional; the extra
        # kwh falls over B's minimum quota and is billed at its over-rate 14
        self.assertEqual(14, makeup[0]['amount'])
        self.assertTrue(store.one(
            self.db, "SELECT 1 FROM heat_escrow WHERE state='released'"))

    def test_bounced_payment_reverses_money_and_blocks_refund(self):
        base_evidence(self.db)
        hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P1',
                            'mode': 'provisional_capped',
                            'authorized_by': 'joint', 'authorized_at': 610})
        b_bill = store.one(self.db,
                           "SELECT * FROM heat_bills WHERE buyer='buyer-B' AND kind='provisional_capped'")
        hr.handle(self.db, {'op': 'pay', 'id': 'pay-bounce', 'bill': b_bill['id'],
                            'amount': 512, 'at': 620})
        bounced = hr.handle(self.db, {'op': 'bounce', 'id': 'pay-bounce',
                                      'at': 630})
        self.assertEqual('payment_reversed', bounced['decision'])
        self.assertEqual('issued', store.one(
            self.db, 'SELECT state FROM heat_bills WHERE id=?',
            (b_bill['id'],))['state'])
        self.assertEqual('returned', store.one(
            self.db, 'SELECT state FROM heat_escrow WHERE bill=?',
            (b_bill['id'],))['state'])
        # no money is held anymore, so no refund can be issued
        rf = hr.handle(self.db, {
            'op': 'recalibrate', 'id': 'RC-B3', 'meter': 'MB',
            'issued_at': 900, 'covers_from': 300, 'covers_to': 600,
            'correction_factor': 9000, 'evidence': 'lab-report-9',
            'period': 'P1'})
        self.assertEqual('credit_recorded', rf['corrections'][0]['decision'])
        self.assertFalse(store.one(self.db, 'SELECT 1 FROM heat_refunds'))

    def test_duplicate_and_unsubstantiated_certificates_are_rejected(self):
        base_evidence(self.db)
        hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P1',
                            'mode': 'provisional_capped',
                            'authorized_by': 'joint', 'authorized_at': 610})
        no_evidence = hr.handle(self.db, {
            'op': 'recalibrate', 'id': 'RC-x', 'meter': 'MB',
            'issued_at': 900, 'covers_from': 300, 'covers_to': 600,
            'correction_factor': 9000, 'evidence': '', 'period': 'P1'})
        self.assertEqual('evidence_required', no_evidence['decision'])
        payload = {'op': 'recalibrate', 'id': 'RC-1', 'meter': 'MB',
                   'issued_at': 900, 'covers_from': 300, 'covers_to': 600,
                   'correction_factor': 9000, 'evidence': 'lab-1',
                   'period': 'P1'}
        # same event id + same payload is an idempotent replay
        first = hr.run(self.db, dict(payload, event_id='rc-1'))
        self.assertEqual('recalibration_applied', first['decision'])
        self.assertEqual(first, hr.run(self.db, dict(payload, event_id='rc-1')))
        # same event id + different payload is an identity conflict
        tampered = dict(payload, event_id='rc-1', correction_factor=8000)
        self.assertEqual('event_identity_conflict',
                         hr.run(self.db, tampered)['decision'])
        # overlapping interval without supersession reference
        conflict = hr.handle(self.db, {
            'op': 'recalibrate', 'id': 'RC-2', 'meter': 'MB',
            'issued_at': 950, 'covers_from': 200, 'covers_to': 600,
            'correction_factor': 8000, 'evidence': 'lab-2', 'period': 'P1'})
        self.assertEqual('unsubstantiated_certificate', conflict['decision'])
        # identical factor for the same meter/interval is a duplicate voucher
        dup = hr.handle(self.db, {
            'op': 'recalibrate', 'id': 'RC-3', 'meter': 'MB',
            'issued_at': 950, 'covers_from': 300, 'covers_to': 600,
            'correction_factor': 9000, 'evidence': 'lab-3', 'period': 'P1'})
        self.assertEqual('certificate_already_recorded', dup['decision'])

    def test_late_certificate_cannot_rewrite_a_finalized_retest_account(self):
        base_evidence(self.db)
        hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P1',
                            'mode': 'retest', 'authorized_by': 'joint',
                            'authorized_at': 610})
        hr.handle(self.db, {'op': 'retest', 'id': 'rt-b', 'period': 'P1',
                            'buyer': 'buyer-B', 'kwh': 20, 'at': 700,
                            'agreed_by': ['plant', 'buyer-B']})
        hr.handle(self.db, {'op': 'retest', 'id': 'rt-a', 'period': 'P1',
                            'buyer': 'buyer-A', 'kwh': 0, 'at': 701,
                            'agreed_by': ['plant', 'buyer-A']})
        before = store.one(self.db,
                           "SELECT * FROM heat_bills WHERE buyer='buyer-B' AND kind='retest_final'")
        late = hr.handle(self.db, {
            'op': 'recalibrate', 'id': 'RC-late', 'meter': 'MB',
            'issued_at': 9000, 'covers_from': 0, 'covers_to': 600,
            'correction_factor': 7000, 'evidence': 'very-late-lab',
            'period': 'P1'})
        self.assertEqual('cert_recorded_retest_final', late['decision'])
        after = store.one(self.db,
                          "SELECT * FROM heat_bills WHERE buyer='buyer-B' AND kind='retest_final'")
        self.assertEqual(dict(before), dict(after))

    def test_meter_swap_retains_old_readings_and_backfill_is_only_disputed(self):
        base_evidence(self.db)
        removed = hr.handle(self.db, {'op': 'remove_meter', 'id': 'MB',
                                      'removed_at': 590})
        self.assertEqual('meter_removed', removed['decision'])
        hr.handle(self.db, {'op': 'branch', 'id': 'MB-2', 'site': SITE,
                            'buyer': 'buyer-B', 'installed_at': 590})
        hr.handle(self.db, {'op': 'certificate', 'id': 'C-B2', 'meter': 'MB-2',
                            'valid_from': 590, 'valid_until': 100000,
                            'issued_at': 595, 'evidence': 'seal-4'})
        # old meter no longer accepts readings
        dead = hr.handle(self.db, {'op': 'reading', 'id': 'r-dead',
                                   'meter': 'MB', 'site': SITE,
                                   'raw_start': 600, 'raw_end': 660,
                                   'kwh': 3, 'calibration': 'C-B'})
        self.assertEqual('meter_not_in_service', dead['decision'])
        live = hr.handle(self.db, {'op': 'reading', 'id': 'r-new',
                                   'meter': 'MB-2', 'site': SITE,
                                   'raw_start': 590, 'raw_end': 660,
                                   'kwh': 3, 'calibration': 'C-B2'})
        self.assertEqual('reading_recorded', live['decision'])
        # outage backfill: original reading retained, but only disputed evidence
        hr.handle(self.db, {'op': 'branch', 'id': 'MC', 'site': SITE,
                            'buyer': 'buyer-A', 'installed_at': -500})
        hr.handle(self.db, {'op': 'certificate', 'id': 'C-C', 'meter': 'MC',
                            'valid_from': -100, 'valid_until': 100000,
                            'issued_at': -50, 'evidence': 'seal-5'})
        hr.handle(self.db, {'op': 'reading', 'id': 'r-c', 'meter': 'MC',
                            'site': SITE, 'raw_start': 0, 'raw_end': 120,
                            'kwh': 5, 'calibration': 'C-C'})
        hr.handle(self.db, {'op': 'provenance', 'reading': 'r-c',
                            'origin': 'backfill', 'recorded_at': 800})
        result = hr.handle(self.db, {'op': 'reconcile', 'id': 'P3',
                                     'site': SITE, 'start_at': START,
                                     'end_at': END})
        self.assertEqual('reconciled', result['decision'])
        backfill = store.many(
            self.db,
            "SELECT * FROM heat_uncertain_intervals WHERE period='P3' AND reason='backfilled_reading'")
        self.assertEqual(5, sum(u['kwh'] for u in backfill))
        # old interval readings remain untouched in the raw store
        self.assertTrue(store.one(self.db,
                                  "SELECT 1 FROM heat_readings WHERE id='r-b'"))

    def test_refund_requires_evidence_and_cannot_exceed_the_payment(self):
        base_evidence(self.db)
        hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P1',
                            'mode': 'provisional_capped',
                            'authorized_by': 'joint', 'authorized_at': 610})
        b_bill = store.one(self.db,
                           "SELECT * FROM heat_bills WHERE buyer='buyer-B' AND kind='provisional_capped'")
        hr.handle(self.db, {'op': 'pay', 'id': 'pay-refund', 'bill': b_bill['id'],
                            'amount': 512, 'at': 620})
        # an unknown payment cannot be refunded at all
        unknown = hr.handle(self.db, {'op': 'refund', 'id': 'rf-u',
                                      'payment': 'pay-ghost', 'amount': 10,
                                      'basis': 'doc', 'at': 700})
        self.assertEqual('payment_unknown', unknown['decision'])
        # a real payment still requires documentary evidence
        no_basis = hr.handle(self.db, {'op': 'refund', 'id': 'rf-0',
                                       'payment': 'pay-refund', 'amount': 10,
                                       'basis': '', 'at': 700})
        self.assertEqual('evidence_required', no_basis['decision'])
        too_much = hr.handle(self.db, {'op': 'refund', 'id': 'rf-1',
                                       'payment': 'pay-refund', 'amount': 513,
                                       'basis': 'doc', 'at': 700})
        self.assertEqual('refund_exceeds_payment', too_much['decision'])
        ok = hr.handle(self.db, {'op': 'refund', 'id': 'rf-2',
                                 'payment': 'pay-refund', 'amount': 512,
                                 'basis': 'doc', 'at': 700})
        self.assertEqual('refund_issued', ok['decision'])
        again = hr.handle(self.db, {'op': 'refund', 'id': 'rf-3',
                                    'payment': 'pay-refund', 'amount': 1,
                                    'basis': 'doc', 'at': 701})
        self.assertEqual('refund_exceeds_payment', again['decision'])

    def test_recalibration_cannot_certify_beyond_the_export_cap(self):
        base_evidence(self.db)
        hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P1',
                            'mode': 'provisional_capped',
                            'authorized_by': 'joint', 'authorized_at': 610})
        for bill in store.many(self.db, 'SELECT id,amount FROM heat_bills'):
            hr.handle(self.db, {'op': 'pay', 'id': f'cap-pay-{bill["id"]}',
                                'bill': bill['id'], 'amount': bill['amount'],
                                'at': 620})
        # an implausibly generous certificate would certify 48 disputed kwh
        # for B alone (24 * 2.0), which would break the calibrated export cap
        out = hr.handle(self.db, {
            'op': 'recalibrate', 'id': 'RC-huge', 'meter': 'MB',
            'issued_at': 900, 'covers_from': 300, 'covers_to': 600,
            'correction_factor': 20000, 'evidence': 'lab-huge',
            'period': 'P1'})
        self.assertEqual('recalibration_applied', out['decision'])
        b = allocation(self.db, 'P1', 'buyer-B')
        # A already holds 21 final kwh, so B may certify at most 100-21=79;
        # provable 24 + capped certified still respects the main-pipe limit
        self.assertLessEqual(
            b['final_kwh'] + allocation(self.db, 'P1', 'buyer-A')['provable_kwh'],
            100)
        self.assertTrue(hr.rebuild_accounts(self.db, 'P1')
                        ['billable_within_export'])

    def test_rebuild_keeps_money_facts_on_the_authorized_path_only(self):
        base_evidence(self.db)
        hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P1',
                            'mode': 'provisional_capped',
                            'authorized_by': 'joint', 'authorized_at': 610})
        b_bill = store.one(self.db,
                           "SELECT * FROM heat_bills WHERE buyer='buyer-B' AND kind='provisional_capped'")
        hr.handle(self.db, {'op': 'pay', 'id': 'pay-view', 'bill': b_bill['id'],
                            'amount': b_bill['amount'], 'at': 620})
        rebuilt = hr.rebuild_accounts(self.db, 'P1')
        self.assertEqual('provisional_capped', rebuilt['authorized_mode'])
        # money only exists under the path that was actually adopted
        self.assertEqual(b_bill['amount'],
                         rebuilt['views']['provisional_capped']['buyer-B']
                         ['paid_amount'])
        self.assertEqual(0,
                         rebuilt['views']['retest']['buyer-B']['paid_amount'])
        self.assertFalse(
            rebuilt['views']['retest']['buyer-B']['is_authorized_path'])
        self.assertTrue(
            rebuilt['views']['provisional_capped']['buyer-B']
            ['is_authorized_path'])
        # the alternative view is still reconstructed from physical evidence
        self.assertEqual(24,
                         rebuilt['views']['retest']['buyer-B']['final_kwh'])

    def test_raw_readings_are_immutable_through_the_full_lifecycle(self):
        base_evidence(self.db)
        hr.handle(self.db, {'op': 'resolve', 'id': 'R1', 'period': 'P1',
                            'mode': 'provisional_capped',
                            'authorized_by': 'joint', 'authorized_at': 610})
        bill = store.one(self.db,
                         "SELECT * FROM heat_bills WHERE buyer='buyer-B' AND kind='provisional_capped'")
        hr.handle(self.db, {'op': 'pay', 'id': 'pay-raw', 'bill': bill['id'],
                            'amount': bill['amount'], 'at': 620})
        hr.handle(self.db, {'op': 'recalibrate', 'id': 'RC-raw', 'meter': 'MB',
                            'issued_at': 900, 'covers_from': 300,
                            'covers_to': 600, 'correction_factor': 9000,
                            'evidence': 'lab', 'period': 'P1'})
        # corrections land in new rows; the original reading interval and the
        # original bill survive untouched and remain joinable as evidence
        reading_row = store.one(self.db,
                                "SELECT * FROM heat_readings WHERE id='r-b'")
        self.assertEqual((300, 900),
                         (reading_row['raw_start'], reading_row['raw_end']))
        self.assertEqual(48, reading_row['kwh'])
        self.assertEqual('corrected',
                         store.one(self.db, 'SELECT state FROM heat_bills WHERE id=?',
                                   (bill['id'],))['state'])
        original = store.one(self.db, 'SELECT billed_kwh FROM heat_invoices WHERE id=?',
                             (bill['id'],))
        # heat_bills and the legacy heat_invoices tables never overwrite rows
        refunds = store.many(self.db, 'SELECT * FROM heat_refunds')
        self.assertTrue(all(r['state'] == 'paid_out' for r in refunds))
        self.assertTrue(all(r['bill'] == bill['id'] for r in refunds))

    def test_full_evidence_flow_replays_through_the_event_store(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            conn = connect(str(Path(tmp) / 'heat.sqlite'))
            events = [
                {'op': 'branch', 'id': 'MA', 'site': SITE, 'buyer': 'buyer-A',
                 'installed_at': -1000, 'at': 1},
                {'op': 'branch', 'id': 'MB', 'site': SITE, 'buyer': 'buyer-B',
                 'installed_at': -1000, 'at': 1},
                {'op': 'clock', 'id': 'c-a', 'meter': 'MA',
                 'offset_seconds': 300, 'observed_at': -10,
                 'applies_from': -1000, 'applies_to': 100000, 'at': 1},
                {'op': 'clock', 'id': 'c-b', 'meter': 'MB',
                 'offset_seconds': 300, 'observed_at': -10,
                 'applies_from': -1000, 'applies_to': 100000, 'at': 1},
                {'op': 'certificate', 'id': 'C-A', 'meter': 'MA',
                 'valid_from': -100, 'valid_until': 100000, 'issued_at': -100,
                 'evidence': 's', 'at': 1},
                {'op': 'certificate', 'id': 'C-B', 'meter': 'MB',
                 'valid_from': -100, 'valid_until': 300, 'issued_at': -200,
                 'evidence': 's', 'at': 1},
                {'op': 'contract', 'id': 'K-A', 'site': SITE,
                 'buyer': 'buyer-A', 'minimum_kwh': 45, 'base_rate': 10,
                 'over_rate': 12, 'shortfall_rate': 3, 'reject_delta': 15,
                 'at': 1},
                {'op': 'contract', 'id': 'K-B', 'site': SITE,
                 'buyer': 'buyer-B', 'minimum_kwh': 40, 'base_rate': 10,
                 'over_rate': 14, 'shortfall_rate': 2, 'reject_delta': 15,
                 'at': 1},
                {'op': 'reading', 'id': 'r-a', 'meter': 'MA', 'site': SITE,
                 'raw_start': 300, 'raw_end': 900, 'kwh': 61,
                 'calibration': 'C-A', 'at': 2},
                {'op': 'reading', 'id': 'r-b', 'meter': 'MB', 'site': SITE,
                 'raw_start': 300, 'raw_end': 900, 'kwh': 48,
                 'calibration': 'C-B', 'at': 2},
            ]
            for i, e in enumerate(events):
                decision = hr.run(conn, dict(e, event_id=f'e{i}'))
                self.assertIn('decision', decision)
            # replay machinery must accept the recorded heat events
            from cloudcourt import MODULES
            self.assertIs(MODULES['heat'], hr)
            self.assertTrue(replay(str(Path(tmp) / 'heat.sqlite'))['verified'])
            conn.close()


if __name__ == '__main__':
    unittest.main()
