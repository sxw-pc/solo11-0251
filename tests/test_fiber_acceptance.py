"""Regression tests for physical fiber acceptance.

The provisional registrar still stamps any two distinct route IDs as
``diverse`` (see ``test_fiber_seed.py``).  These tests pin the acceptance gate
that the customer can actually sign for: evidence must point at one physical
in-service core, diversity must survive splice-box/OTDR/wayleave review, and
the two contractual delivery shapes (permanent dual fiber vs. temporary
wireless) are settled separately.
"""

import sqlite3
import unittest

from cloudcourt.fiber_route import receive
from cloudcourt.circuit_activation import provisional
from cloudcourt import fiber_acceptance as fa


def db_setup():
    db = sqlite3.connect(':memory:')
    db.row_factory = sqlite3.Row
    return db


def seed_route(db, route_id, duct, box, core, lit=1, carrier='carrier',
               capacity=100):
    receive(db, route_id, carrier, duct, box, capacity, 'blue')
    fa.register_core(db, route_id, core, lit=lit)
    fa.record_duct(db, route_id, duct, 'current_survey', 'survey-%s' % route_id)


def file_evidence(db, route_id, core, window_id, *, measured_capacity=100,
                  measured_loss=12.0, state='valid'):
    fa.record_evidence(db, route_id, fa.PURCHASE_ORDER, None,
                       'po-%s' % route_id, core, state)
    fa.record_evidence(db, route_id, fa.WAYLEAVE, None,
                       'wl-%s' % route_id, core, state)
    fa.record_evidence(db, route_id, fa.FIELD_LABEL, None,
                       'label-%s' % route_id, core, state)
    fa.record_evidence(db, route_id, fa.BOX_WITNESS, None,
                       'witness-%s' % route_id, core, state)
    fa.record_evidence(db, route_id, fa.LOAD_TEST, window_id,
                       'load-%s' % route_id, core, state, measured_capacity)
    fa.record_evidence(db, route_id, fa.ATTENUATION, window_id,
                       'loss-%s' % route_id, core, state, measured_loss)
    # The resolver probe is filed by the witnessed cut test, not pre-staged.


def traces(db, route_id, core, window_id, dist_a, dist_b, drawing=None):
    fa.record_trace(db, 'tr-%s-A' % route_id, route_id, core, 'A', window_id,
                    dist_a, drawing or route_id)
    fa.record_trace(db, 'tr-%s-B' % route_id, route_id, core, 'B', window_id,
                    dist_b, drawing or route_id)


def open_window(db, window_id='W1', tenant='tenant-A'):
    fa.open_window(db, window_id, tenant, capacity_required=100, max_loss=20.0,
                   max_switchover_ms=50, probe_required=1, started_at=100,
                   closed_at=200)


def build_independent_pair(db, window_id='W1', tenant='tenant-A',
                           activation='C1'):
    """A fully evidenced, genuinely diverse pair (east route + north route)."""
    seed_route(db, 'F1', 'duct-E', 'box-E', 'core-1')
    seed_route(db, 'F2', 'duct-N', 'box-N', 'core-2')
    fa.register_box(db, 'box-E', 'E-label', 'E-label', 'east chamber')
    fa.register_box(db, 'box-N', 'N-label', 'N-label', 'north chamber')
    fa.attach_route_box(db, 'F1', 'box-E', 'core-1', 'wit-E')
    fa.attach_route_box(db, 'F2', 'box-N', 'core-2', 'wit-N')
    # Old datum registry once wrote both routes into the same duct; the
    # historical entry is retained but the independent north route survives.
    fa.record_duct(db, 'F2', 'duct-X', 'legacy_datum_registry', 'old-map')
    for route_id, core, dist in (('F1', 'core-1', 310.0),
                                 ('F2', 'core-2', 780.0)):
        traces(db, route_id, core, window_id, dist, dist + 50.0)
        file_evidence(db, route_id, core, window_id)
    open_window(db, window_id, tenant)
    state = provisional(db, activation, tenant, 'F1', 'F2')
    return state


def schedule_and_pass_cut(db, activation='C1', route_id='F1',
                          window_id='W1', switchover=30, test_id='CT1'):
    fa.schedule_cut_test(db, test_id, activation, route_id, window_id,
                         'customer-signed-consent', 150)
    return fa.record_cut_result(db, test_id, switchover, 'passed', probe_ok=True)


class FiberAcceptanceTest(unittest.TestCase):
    def setUp(self):
        self.db = db_setup()

    def tearDown(self):
        self.db.close()

    def _reasons(self, result):
        return set(result['reasons'])

    def test_same_duct_same_box_pair_is_rejected_even_with_full_evidence(self):
        build_independent_pair(self.db)
        # Rebuild the actual disputed pair: two IDs, one trench and one box.
        db = sqlite3.connect(':memory:')
        db.row_factory = sqlite3.Row
        seed_route(db, 'F1', 'duct-X', 'box-1', 'core-1', carrier='carrier-A')
        seed_route(db, 'F2', 'duct-X', 'box-1', 'core-2', carrier='carrier-B')
        fa.register_box(db, 'box-1', 'box-1', 'box-1', 'shared chamber')
        fa.attach_route_box(db, 'F1', 'box-1', 'core-1', 'wit-1')
        fa.attach_route_box(db, 'F2', 'box-1', 'core-2', 'wit-2')
        traces(db, 'F1', 'core-1', 'W1', 420.0, 900.0)
        traces(db, 'F2', 'core-2', 'W1', 422.0, 898.0)
        file_evidence(db, 'F1', 'core-1', 'W1')
        file_evidence(db, 'F2', 'core-2', 'W1')
        open_window(db)
        self.assertEqual('diverse', provisional(db, 'C1', 'tenant-A', 'F1', 'F2'))
        schedule_and_pass_cut(db)
        result = fa.evaluate(db, 'C1', 'W1', 160)
        self.assertEqual('rejected', result['state'])
        reasons = self._reasons(result)
        self.assertIn('shared_duct', reasons)
        self.assertIn('shared_splice_box', reasons)
        self.assertIn('otdr_shared_reflection:end_A', reasons)
        self.assertIn('otdr_shared_reflection:end_B', reasons)
        db.close()

    def test_relabeled_box_is_tracked_and_unnoticed_relabel_blocks_acceptance(self):
        build_independent_pair(self.db)
        # One physical box, relabeled so the two routes appear to use two.
        fa.register_box(self.db, 'box-9', 'old-label', 'east-tag', 'chamber 9')
        fa.relabel_box(self.db, 'box-9', 'north-tag')  # no customer notice
        fa.attach_route_box(self.db, 'F1', 'box-9', 'core-1', 'wit-1')
        fa.attach_route_box(self.db, 'F2', 'box-9', 'core-2', 'wit-2')
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        self.assertEqual('rejected', result['state'])
        reasons = self._reasons(result)
        self.assertIn('shared_splice_box', reasons)
        self.assertIn('relabel_without_customer_notice', reasons)
        # The old label path is retained for the notification trail.
        history = self.db.execute(
            'SELECT * FROM splice_box_history WHERE box_id=?', ('box-9',)).fetchone()
        self.assertEqual('east-tag', history['old_label'])
        self.assertEqual('north-tag', history['new_label'])
        self.assertIsNone(history['notice_ref'])

    def test_relabel_with_customer_notice_keeps_history_but_shared_box_still_fails(self):
        build_independent_pair(self.db)
        fa.register_box(self.db, 'box-9', 'old-label', 'east-tag', 'chamber 9')
        notice = fa.relabel_box(self.db, 'box-9', 'north-tag',
                                notice_ref='notice-77')
        self.assertEqual('box_relabeled', notice['decision'])
        fa.attach_route_box(self.db, 'F1', 'box-9', 'core-1', 'wit-1')
        fa.attach_route_box(self.db, 'F2', 'box-9', 'core-2', 'wit-2')
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        reasons = self._reasons(result)
        self.assertIn('shared_splice_box', reasons)
        self.assertNotIn('relabel_without_customer_notice', reasons)

    def test_dual_end_trace_conflict_is_detected_at_equal_distance(self):
        build_independent_pair(self.db)
        # Supplier drawings say east vs. north, but both A-end curves show a
        # reflection at the same distance from the site.
        fa.record_trace(self.db, 'tr-F1-A2', 'F1', 'core-1', 'A', 'W1',
                        555.0, 'F1')
        fa.record_trace(self.db, 'tr-F2-A2', 'F2', 'core-2', 'A', 'W1',
                        557.0, 'F2')
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        self.assertIn('otdr_shared_reflection:end_A', self._reasons(result))
        self.assertEqual('rejected', result['state'])

    def test_drawing_that_points_at_other_route_flags_conflict(self):
        build_independent_pair(self.db)
        fa.record_trace(self.db, 'tr-F2-B-conflict', 'F2', 'core-2', 'B',
                        'W1', 900.0, drawing_route='F1')
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        self.assertIn('drawings_conflict_with_traces', self._reasons(result))

    def test_spare_core_evidence_cannot_represent_in_service_core(self):
        build_independent_pair(self.db)
        # The spare core is tested empty.  The only box binding and witness
        # paperwork left for F1 points at the spare, not the in-service core.
        fa.register_core(self.db, 'F1', 'core-1-spare', lit=0, state='spare')
        self.db.execute(
            "DELETE FROM route_boxes WHERE route_id='F1' AND core_id='core-1'")
        fa.attach_route_box(self.db, 'F1', 'box-E', 'core-1-spare',
                            'spare-witness')
        fa.record_evidence(self.db, 'F1', fa.BOX_WITNESS, None,
                           'spare-witness', 'core-1-spare')
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        reasons = self._reasons(result)
        self.assertIn('evidence_core_mismatch:box_witness', reasons)
        self.assertIn('in_service_witness_missing', reasons)
        self.assertEqual('rejected', result['state'])

    def test_witnessed_cut_test_failure_rejects_permanent_acceptance(self):
        build_independent_pair(self.db)
        fa.schedule_cut_test(self.db, 'CT1', 'C1', 'F1', 'W1',
                             'customer-signed-consent', 150)
        fa.record_cut_result(self.db, 'CT1', 30, 'failed', probe_ok=False)
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        reasons = self._reasons(result)
        self.assertIn('cut_test_failed', reasons)
        self.assertIn('resolver_probe_failed', reasons)
        self.assertEqual('rejected', result['state'])

    def test_switchover_over_contract_limit_rejects(self):
        build_independent_pair(self.db)
        fa.schedule_cut_test(self.db, 'CT1', 'C1', 'F1', 'W1',
                             'customer-signed-consent', 150)
        fa.record_cut_result(self.db, 'CT1', 80, 'passed', probe_ok=True)
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        self.assertIn('switchover_over_limit', self._reasons(result))
        self.assertEqual('rejected', result['state'])

    def test_cut_test_requires_signed_customer_consent(self):
        build_independent_pair(self.db)
        denied = fa.schedule_cut_test(self.db, 'CT1', 'C1', 'F1', 'W1',
                                      '', 150)
        self.assertEqual('customer_consent_required', denied['decision'])

    def test_without_cut_test_evidence_is_complete_but_not_accepted(self):
        build_independent_pair(self.db)
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        self.assertEqual('evidence_complete_pending_witness', result['state'])
        self.assertIn('witnessed_cut_test_missing', self._reasons(result))

    def test_pending_cut_test_does_not_mask_other_hard_failures(self):
        build_independent_pair(self.db)
        fa.record_evidence(self.db, 'F2', fa.LOAD_TEST, 'W1', 'load-low',
                           'core-2', 'valid', 40)
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        # No cut test yet, but the capacity failure forces a hard rejection
        # rather than an optimistic "pending witness" state.
        self.assertEqual('rejected', result['state'])
        reasons = self._reasons(result)
        self.assertIn('capacity_below_contract', reasons)
        self.assertIn('witnessed_cut_test_missing', reasons)

    def test_independent_north_route_passes_permanent_acceptance(self):
        build_independent_pair(self.db)
        schedule_and_pass_cut(self.db)
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        self.assertEqual('permanent_accepted', result['state'])
        self.assertEqual('fiber', result['medium'])
        self.assertEqual(
            'permanent_dual_fiber',
            fa.protection_state(self.db, 'C1', 160)['state'])

    def test_capacity_below_contract_requirement_rejects(self):
        build_independent_pair(self.db)
        fa.record_evidence(self.db, 'F2', fa.LOAD_TEST, 'W1', 'load-low',
                           'core-2', 'valid', 40)
        schedule_and_pass_cut(self.db)
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        self.assertIn('capacity_below_contract', self._reasons(result))
        self.assertEqual('rejected', result['state'])

    def test_attenuation_over_limit_rejects(self):
        build_independent_pair(self.db)
        fa.record_evidence(self.db, 'F1', fa.ATTENUATION, 'W1', 'loss-high',
                           'core-1', 'valid', 24.5)
        schedule_and_pass_cut(self.db)
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        self.assertIn('attenuation_over_limit', self._reasons(result))
        self.assertEqual('rejected', result['state'])

    def test_measurements_must_come_from_the_same_window(self):
        build_independent_pair(self.db)
        # Move F1's load test into an older window; the slot in W1 is removed.
        self.db.execute(
            "DELETE FROM route_evidence WHERE route_id='F1' AND evidence_type=? "
            "AND window_id='W1'", (fa.LOAD_TEST,))
        fa.record_evidence(self.db, 'F1', fa.LOAD_TEST, 'W0', 'old-load',
                           'core-1', 'valid', 100)
        schedule_and_pass_cut(self.db)
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        self.assertIn('measurement_not_same_window:load_test',
                      self._reasons(result))
        self.assertEqual('rejected', result['state'])

    def test_unlit_planned_route_cannot_take_protection_slot(self):
        seed_route(self.db, 'F1', 'duct-E', 'box-E', 'core-1')
        # F2 is only a planned route: no light, no service.
        seed_route(self.db, 'F2', 'duct-N', 'box-N', 'core-2', lit=0)
        fa.register_box(self.db, 'box-E', 'E-label', 'E-label', 'east')
        fa.register_box(self.db, 'box-N', 'N-label', 'N-label', 'north')
        fa.attach_route_box(self.db, 'F1', 'box-E', 'core-1', 'wit-E')
        traces(self.db, 'F1', 'core-1', 'W1', 310.0, 360.0)
        file_evidence(self.db, 'F1', 'core-1', 'W1')
        open_window(self.db)
        provisional(self.db, 'C1', 'tenant-A', 'F1', 'F2')
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        self.assertEqual('rejected', result['state'])
        self.assertIn('route_not_lit', self._reasons(result))

    def test_wireless_licence_expiry_blocks_temporary_protection(self):
        build_independent_pair(self.db)
        reg = fa.register_wireless(self.db, 'R1', 'tenant-A', 'freq-lic-1',
                                   150, 'receipt-1', 200, 18, at=160)
        self.assertEqual('wireless_licence_expired', reg['decision'])
        denied = fa.activate_temporary(self.db, 'TP1', 'C1', 'R1', 160)
        self.assertEqual('temporary_protection_unavailable', denied['decision'])
        self.assertEqual('none',
                         fa.protection_state(self.db, 'C1', 160)['state'])

    def test_wireless_requires_licence_and_connectivity_receipt(self):
        self.assertEqual(
            'frequency_licence_required',
            fa.register_wireless(self.db, 'R2', 'tenant-A', '', 300,
                                 'receipt-2', 200, 18, at=100)['decision'])
        self.assertEqual(
            'connectivity_receipt_required',
            fa.register_wireless(self.db, 'R3', 'tenant-A', 'lic-3', 300,
                                 '', 200, 18, at=100)['decision'])

    def test_temporary_wireless_protects_but_never_fills_permanent_slot(self):
        build_independent_pair(self.db)
        fa.register_wireless(self.db, 'R1', 'tenant-A', 'freq-lic-1', 500,
                             'receipt-1', 200, 18, at=160)
        fa.activate_temporary(self.db, 'TP1', 'C1', 'R1', 160)
        state = fa.protection_state(self.db, 'C1', 170)
        self.assertEqual('temporary_wireless', state['state'])
        self.assertEqual('wireless', state['medium'])
        # Permanent acceptance is still not earned while the cut test is open.
        result = fa.evaluate(self.db, 'C1', 'W1', 170)
        self.assertEqual('evidence_complete_pending_witness', result['state'])
        # No "wireless OR north route" credit after the licence lapses.
        self.assertEqual('none',
                         fa.protection_state(self.db, 'C1', 501)['state'])
        fa.deactivate_temporary(self.db, 'TP1', 200)
        self.assertEqual('none',
                         fa.protection_state(self.db, 'C1', 201)['state'])

    def test_install_fee_unearned_until_permanent_acceptance_and_settles_apart(self):
        build_independent_pair(self.db)
        fa.collect_install_fee(self.db, 'C1', 'tenant-A', 5000, 90)
        # Acceptance late relative to collection: fee stays unearned.
        pending = fa.settlement_report(self.db, 'C1')
        self.assertFalse(pending['install_fee_earned'])
        self.assertEqual('not_accepted', pending['acceptance_state'])
        schedule_and_pass_cut(self.db)
        fa.evaluate(self.db, 'C1', 'W1', 160)
        report = fa.settlement_report(self.db, 'C1')
        self.assertTrue(report['install_fee_earned'])
        self.assertEqual(160, report['install_fee']['earned_at'])
        kinds = [e['kind'] for e in report['entries']]
        self.assertEqual(['permanent_install_fee'], kinds)
        # Service acceptance conveys neither title nor wayleave.
        self.assertFalse(report['conveys_ownership'])
        self.assertFalse(report['conveys_wayleave'])

    def test_temporary_service_billed_separately_from_install_fee(self):
        build_independent_pair(self.db)
        fa.collect_install_fee(self.db, 'C1', 'tenant-A', 5000, 90)
        fa.register_wireless(self.db, 'R1', 'tenant-A', 'freq-lic-1', 500,
                             'receipt-1', 200, 18, at=160)
        fa.activate_temporary(self.db, 'TP1', 'C1', 'R1', 160)
        self.db.execute(
            'INSERT INTO settlement_entries VALUES(?,?,?,?,?,?)',
            ('bill-temp-1', 'C1', 'temporary_wireless_service', 300, 190,
             'dated protection service'))
        report = fa.settlement_report(self.db, 'C1')
        self.assertFalse(report['install_fee_earned'])
        self.assertEqual(
            ['temporary_wireless_service'],
            [e['kind'] for e in report['entries']])

    def test_carrier_name_and_colour_never_prove_diversity(self):
        # Exactly the seed scenario from the provisional registrar.
        receive(self.db, 'F1', 'carrier-A', 'duct-X', 'box-1', 40, 'blue')
        receive(self.db, 'F2', 'carrier-B', 'duct-X', 'box-1', 40, 'green')
        self.assertEqual('diverse',
                         provisional(self.db, 'C1', 'tenant-A', 'F1', 'F2'))
        open_window(self.db)
        result = fa.evaluate(self.db, 'C1', 'W1', 160)
        self.assertEqual('rejected', result['state'])
        reasons = self._reasons(result)
        self.assertIn('shared_duct', reasons)
        self.assertIn('route_not_lit', reasons)

    def test_unknown_activation_and_missing_window_are_rejected(self):
        open_window(self.db)
        result = fa.evaluate(self.db, 'ghost', 'W1', 160)
        self.assertEqual('rejected', result['state'])
        self.assertIn('activation_not_registered', self._reasons(result))

    def test_dispatch_run_unknown_operation(self):
        self.assertEqual({'decision': 'unknown_operation'},
                         fa.run(self.db, {'op': 'nope'}))


if __name__ == '__main__':
    unittest.main()
