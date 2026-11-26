import json
import unittest

from cloudcourt import rf_resolution, rf_survey
from cloudcourt.store import connect


def run(db, **payload):
    payload.setdefault('event_id', f"evt-{run.counter}")
    run.counter += 1
    return rf_resolution.run(db, payload)


run.counter = 0


class Base(unittest.TestCase):
    def setUp(self):
        self.db = connect(':memory:')
        run.counter = 0

    def tearDown(self):
        self.db.close()

    def site(self, **over):
        payload = dict(op='site', site='S', neighbor_site='N',
                       neighbor_capacity_mbps=500, customer_capacity_mbps=800,
                       customer_latency_ms=20)
        payload.update(over)
        return run(self.db, **payload)

    def receiver(self, required=5, position='neighbor-original', config='c1'):
        return run(self.db, op='receiver', id='rcvr', site='S',
                   position=position, config=config,
                   required_errors=required, at=1)

    def trial(self, psu, carrier, errors, at, experiment='E', config='c1',
              receiver='rcvr', baseline=5, load_pct=90):
        return run(self.db, op='trial', id=f'T{at}', site='S', experiment=experiment,
                   config=config, receiver=receiver, psu_on=psu,
                   carrier_on=carrier, load_pct=load_pct, baseline=baseline,
                   errors=errors, at=at)

    def four_combinations(self, experiment='E', config='c1', receiver='rcvr',
                          both=(100, 110), psu_only=60, carrier_only=65,
                          both_off=0):
        self.trial(True, True, both[0], 10, experiment, config, receiver)
        self.trial(True, False, psu_only, 11, experiment, config, receiver)
        self.trial(False, True, carrier_only, 12, experiment, config, receiver)
        self.trial(False, False, both_off, 13, experiment, config, receiver)
        self.trial(True, True, both[1], 14, experiment, config, receiver)

    def diagnose(self, **over):
        payload = dict(op='diagnose', site='S', experiment='E', receiver='rcvr',
                       config='c1', load_pct=90, tolerance=20, at=20)
        payload.update(over)
        return run(self.db, **payload)


class FiveCombinationTrials(Base):
    def setUp(self):
        super().setUp()
        self.site()
        self.receiver()

    def test_diagnosis_does_not_pick_a_single_source(self):
        self.four_combinations()
        result = self.diagnose()
        self.assertEqual(result['decision'], 'diagnosed')
        self.assertEqual(result['attribution'], 'not_attributable_to_single_source')
        self.assertIn('two_independent_leaks', result['candidates'])
        self.assertIn('shared_ground_nonlinear_coupling', result['candidates'])
        intermod = [r for r in result['ruled_out']
                    if r['candidate'] == 'neighbor_receiver_intermod_as_sole_cause']
        self.assertTrue(intermod)
        self.assertTrue(result['single_action']['psu_removal_alone_insufficient'])
        self.assertTrue(result['single_action']['carrier_removal_alone_insufficient'])
        self.assertNotIn(result['verdict'], ('psu', 'carrier'))
        self.assertIn('post_action_joint_spike_retest',
                      result['required_discriminators'])

    def test_averaging_or_maximum_never_names_one_device(self):
        self.four_combinations()
        first = self.diagnose(experiment='E')
        # A second experiment with only the maximum/mean would still be ambiguous.
        for offset, errors in enumerate((100, 110, 120), start=30):
            self.trial(True, True, errors, offset, experiment='E2')
        for offset, (psu, carrier, errors) in enumerate(
                ((True, False, 60), (False, True, 65), (False, False, 0)), start=40):
            self.trial(psu, carrier, errors, offset, experiment='E2')
        second = self.diagnose(experiment='E2', at=50)
        for result in (first, second):
            self.assertNotIn(result['verdict'], ('psu', 'carrier'))
            self.assertIn('two_independent_leaks', result['candidates'])

    def test_missing_combination_is_incomplete_not_guessed(self):
        self.trial(True, True, 100, 10)
        result = self.diagnose()
        self.assertEqual(result['decision'], 'experiment_incomplete')
        self.assertIn('psu_on=1,carrier_on=0', result['missing'])

    def test_unstable_repeats_block_conclusion(self):
        self.four_combinations(both=(20, 120))
        result = self.diagnose()
        self.assertIn('repeatability_exceeded', result['blockers'])
        self.assertNotEqual(result['verdict'], 'no_measurable_effect')

    def test_background_impairment_is_not_called_no_effect(self):
        self.four_combinations(both=(5, 8), psu_only=0, carrier_only=0,
                               both_off=40)
        result = self.diagnose()
        self.assertEqual(result['verdict'],
                         'receiver_impaired_before_intervention')
        self.assertIn('background_above_baseline', result['blockers'])
        self.assertIn('neighbor_receiver_impaired', result['candidates'])

    def test_joint_only_failure_points_to_receiver_or_common_path(self):
        self.four_combinations(both=(100, 105), psu_only=0, carrier_only=0,
                               both_off=0)
        result = self.diagnose()
        self.assertEqual(result['verdict'], 'joint_only_effect')
        self.assertIn('neighbor_receiver_intermod', result['candidates'])
        self.assertIn('joint_common_path_coupling', result['candidates'])


class SharedGroundCoupling(Base):
    def setUp(self):
        super().setUp()
        self.site()
        self.receiver()

    def test_super_additive_points_to_shared_ground_not_single_source(self):
        # 30 + 40 = 70 if independent, but joint 110 when a shared ground path
        # couples them non-linearly: the common-path candidate leads.
        self.four_combinations(both=(105, 110), psu_only=30, carrier_only=40)
        result = self.diagnose()
        self.assertEqual(result['verdict'], 'super_additive_common_path')
        self.assertEqual(result['candidates'][0], 'shared_ground_nonlinear_coupling')
        self.assertEqual(result['attribution'], 'not_attributable_to_single_source')

    def test_single_psu_removal_is_reported_insufficient(self):
        self.four_combinations()
        result = self.diagnose()
        self.assertIn('psu_removal_alone_insufficient', result['blockers'])
        self.assertIn('carrier_removal_alone_insufficient', result['blockers'])


class MeasurementPointAndCalibration(Base):
    def setUp(self):
        super().setUp()
        self.site()
        self.receiver()

    def sample(self, sample_id, at, field, load=90, point='neighbor-original',
               config='c1', calibrated_until=100, bandwidth=200,
               antenna='sector-3', instrument='probe-A'):
        return run(self.db, op='sample', id=sample_id, site='S',
                   frequency_khz=30000, at=at, field_mv=field,
                   instrument=instrument, bandwidth_khz=bandwidth,
                   calibrated_until=calibrated_until, antenna=antenna,
                   point=point, load_pct=load, config=config)

    def test_point_difference_prevents_borrowing_a_clear_reading(self):
        self.sample('idle-far', 10, 10, load=0, point='far-field')
        self.sample('loaded-near', 11, 90, load=90, point='neighbor-original')
        result = run(self.db, op='provisional', id='C', site='S',
                     frequency_khz=30000, limit_mv=50, config='c1',
                     point='far-field', at=12)
        self.assertEqual(result['decision'], 'blocked')
        self.assertIn('exceedance_at_other_point', result['reasons'])
        self.assertIn('no_loaded_measurement', result['reasons'])

    def test_expired_instrument_cannot_support_clearance(self):
        self.sample('s1', 10, 10, load=90, calibrated_until=5)
        result = run(self.db, op='provisional', id='C', site='S',
                     frequency_khz=30000, limit_mv=50, config='c1',
                     point='neighbor-original', at=12)
        self.assertEqual(result['decision'], 'blocked')
        self.assertIn('instrument_calibration_expired', result['reasons'])

    def test_missing_bandwidth_or_antenna_is_not_clear(self):
        # Bypass the sample-time guard to prove the clearance layer also
        # refuses legacy rows lacking provenance.
        rf_survey.record(self.db, 's1', 'S', 30000, 10, 10, 'probe-A',
                         0, 100, None, 'neighbor-original', 90, 'c1')
        result = run(self.db, op='provisional', id='C', site='S',
                     frequency_khz=30000, limit_mv=50, config='c1',
                     point='neighbor-original', at=12)
        self.assertEqual(result['decision'], 'blocked')
        self.assertIn('bandwidth_unspecified', result['reasons'])
        self.assertIn('antenna_orientation_unspecified', result['reasons'])

    def test_loaded_sample_low_is_clear(self):
        self.sample('s1', 10, 10, load=90)
        result = run(self.db, op='provisional', id='C', site='S',
                     frequency_khz=30000, limit_mv=50, config='c1',
                     point='neighbor-original', at=12)
        self.assertEqual(result['decision'], 'clear')

    def test_idle_measurement_alone_cannot_clear(self):
        self.sample('s1', 10, 10, load=0)
        result = run(self.db, op='provisional', id='C', site='S',
                     frequency_khz=30000, limit_mv=50, config='c1',
                     point='neighbor-original', at=12)
        self.assertEqual(result['decision'], 'blocked')
        self.assertIn('no_loaded_measurement', result['reasons'])

    def test_sample_missing_provenance_is_refused(self):
        for payload in (
                dict(bandwidth=0, antenna='sector-3', point='neighbor-original',
                     calibrated_until=100),
                dict(bandwidth=200, antenna=None, point='neighbor-original',
                     calibrated_until=100),
                dict(bandwidth=200, antenna='sector-3', point=None,
                     calibrated_until=100),
                dict(bandwidth=200, antenna='sector-3', point='neighbor-original',
                     calibrated_until=None)):
            result = run(self.db, op='sample', id='bad', site='S',
                         frequency_khz=30000, at=10, field_mv=10,
                         instrument='probe-A', load_pct=90, config='c1',
                         **payload)
            self.assertIn(result['decision'],
                          ('bandwidth_unspecified', 'antenna_or_point_required',
                           'instrument_calibration_unverified'))

    def test_other_configuration_sample_does_not_qualify(self):
        self.sample('s1', 10, 10, load=90, config='other')
        result = run(self.db, op='provisional', id='C', site='S',
                     frequency_khz=30000, limit_mv=50, config='c1',
                     point='neighbor-original', at=12)
        self.assertEqual(result['decision'], 'blocked')
        self.assertIn('no_sample_for_config', result['reasons'])


class FilterFailureAndRollback(Base):
    def setUp(self):
        super().setUp()
        self.site()
        self.receiver()

    def filters_installed(self):
        run(self.db, op='action', id='filter', site='S', kind='psu_filter',
            config_before='c1', config_after='c2', at=10)
        run(self.db, op='action', id='ground', site='S', kind='bridge_ground',
            config_before='c2', config_after='c3', at=11)
        run(self.db, op='action', id='revert', site='S', kind='remove_filter',
            branch='in_place', config_before='c3', config_after='c4', at=60)

    def test_retest_after_filter_removal_is_rejected(self):
        self.filters_installed()
        result = run(self.db, op='retest', id='rt', action='ground', site='S',
                     config='c3', mode='local_joint_spike', receiver='rcvr',
                     position='neighbor-original', psu_on=True, carrier_on=True,
                     errors=1, baseline=0, instrument='probe-A',
                     calibrated_until=100, local_neighbor=True,
                     local_customer=True, at=70)
        self.assertEqual(result['decision'], 'action_rolled_back')

    def test_old_clearance_and_signatures_are_invalidated(self):
        run(self.db, op='action', id='filter', site='S', kind='psu_filter',
            config_before='c1', config_after='c2', at=10)
        run(self.db, op='action', id='ground', site='S', kind='bridge_ground',
            config_before='c2', config_after='c3', at=11)
        run(self.db, op='sample', id='s1', site='S', frequency_khz=30000,
            at=12, field_mv=10, instrument='probe-A', bandwidth_khz=200,
            calibrated_until=100, antenna='sector-3', point='neighbor-original',
            load_pct=90, config='c3')
        self.assertEqual(run(self.db, op='provisional', id='C', site='S',
                             frequency_khz=30000, limit_mv=50, config='c3',
                             point='neighbor-original', at=13)['decision'], 'clear')
        run(self.db, op='action', id='revert2', site='S', kind='remove_filter',
            branch='in_place', config_before='c3', config_after='c4', at=80)
        state = run(self.db, op='clearance_status', id='C')
        self.assertEqual(state['decision'], 'blocked')
        self.assertIn('withdrawn', state['reasons'])

    def test_resolution_fences_configuration_windows(self):
        self.filters_installed()
        report = run(self.db, op='resolution', site='S')
        self.assertEqual(report['decision'], 'resolution_reported')
        self.assertEqual(report['delivery']['state'], 'not_delivered')
        configs = {w['config'] for w in report['windows']}
        self.assertIn('c1', configs)
        self.assertIn('c3', configs)
        self.assertTrue(all(w['state'] != 'clear' for w in report['windows']))


class PermitValidity(Base):
    def setUp(self):
        super().setUp()
        self.site()
        self.receiver(config='c1')
        run(self.db, op='permit', id='permit-1', site='S', position='roof-1',
            issuer='regulator', at=1)
        run(self.db, op='action', id='roof', site='S',
            kind='relocate_carrier_antenna', config_before='c1',
            config_after='c2', position='roof-1', permit='permit-1', at=10)
        run(self.db, op='receiver', id='rcvr', site='S',
            position='neighbor-original', config='c2', required_errors=5, at=11)

    def test_revoked_roof_permit_blocks_retest(self):
        run(self.db, op='permit', id='permit-1', site='S', position='roof-1',
            issuer='regulator', at=12, state='revoked')
        result = run(self.db, op='retest', id='rt', action='roof', site='S',
                     config='c2', mode='local_joint_spike', receiver='rcvr',
                     position='neighbor-original', psu_on=True, carrier_on=True,
                     errors=1, baseline=0, instrument='probe-A',
                     calibrated_until=100, local_neighbor=True,
                     local_customer=True, at=20)
        self.assertEqual(result['decision'], 'permit_revoked')

    def test_permit_renewal_or_revocation_decision(self):
        renewed = run(self.db, op='permit', id='permit-1', site='S',
                      position='roof-1', issuer='regulator', at=12)
        self.assertEqual(renewed['decision'], 'permit_active')
        revoked = run(self.db, op='permit', id='permit-1', site='S',
                      position='roof-1', issuer='regulator', at=13,
                      state='revoked')
        self.assertEqual(revoked['decision'], 'permit_revoked')
        moved = run(self.db, op='permit', id='permit-1', site='S',
                    position='roof-9', issuer='regulator', at=14)
        self.assertEqual(moved['decision'], 'permit_identity_conflict')


class ActionPrerequisites(Base):
    def setUp(self):
        super().setUp()
        self.site()
        self.receiver()

    def test_licensed_roof_permit_required_for_antenna_move(self):
        denied = run(self.db, op='action', id='m1', site='S',
                     kind='relocate_carrier_antenna', config_before='c1',
                     config_after='c2', position='roof-1', at=10)
        self.assertEqual(denied['decision'], 'permit_required')
        run(self.db, op='permit', id='permit-1', site='S', position='roof-1',
            issuer='regulator', at=1)
        wrong = run(self.db, op='action', id='m2', site='S',
                    kind='relocate_carrier_antenna', config_before='c1',
                    config_after='c2', position='roof-2', permit='permit-1',
                    at=11)
        self.assertEqual(wrong['decision'], 'permit_position_mismatch')
        allowed = run(self.db, op='action', id='m3', site='S',
                      kind='relocate_carrier_antenna', config_before='c1',
                      config_after='c2', position='roof-1', permit='permit-1',
                      at=12)
        self.assertEqual(allowed['decision'], 'action_committed')

    def test_unlicensed_position_is_rejected_even_with_permit_record(self):
        run(self.db, op='permit', id='permit-2', site='S', position='basement',
            issuer='self', at=1)
        result = run(self.db, op='action', id='m', site='S',
                     kind='relocate_carrier_antenna', config_before='c1',
                     config_after='c2', position='basement', permit='permit-2',
                     at=10)
        self.assertEqual(result['decision'], 'permit_position_not_licensed_roof')

    def test_migration_requires_uplink_up(self):
        no_cabinet = run(self.db, op='action', id='mg1', site='S',
                         kind='migrate_resolution', config_before='c1',
                         config_after='c2', cabinet_state='accepted',
                         uplink='down', at=10)
        self.assertEqual(no_cabinet['decision'], 'uplink_unverified')
        no_accept = run(self.db, op='action', id='mg2', site='S',
                        kind='migrate_resolution', config_before='c1',
                        config_after='c2', cabinet_state='pending',
                        uplink='up', at=11)
        self.assertEqual(no_accept['decision'], 'cabinet_not_accepted')

    def test_action_cannot_skip_configuration(self):
        run(self.db, op='action', id='a1', site='S', kind='psu_filter',
            config_before='c1', config_after='c2', at=10)
        skip = run(self.db, op='action', id='a2', site='S', kind='bridge_ground',
                   config_before='c5', config_after='c6', at=11)
        self.assertEqual(skip['decision'], 'configuration_discontinuity')


class BranchDelivery(Base):
    def setUp(self):
        super().setUp()
        self.site()
        self.receiver()

    def do_in_place(self):
        run(self.db, op='action', id='filter', site='S', kind='psu_filter',
            config_before='c1', config_after='c2', at=10)
        run(self.db, op='action', id='ground', site='S', kind='bridge_ground',
            config_before='c2', config_after='c3', at=11)
        # The neighbour re-confirms its acceptance for the rebuilt equipment
        # state; the old acceptance belonged to cfg-1.
        run(self.db, op='receiver', id='rcvr', site='S',
            position='neighbor-original', config='c3', required_errors=5,
            at=12)

    def passing_retest(self, action='ground', config='c3', at=20, errors=2,
                       instrument='probe-A', calibrated_until=100,
                       position='neighbor-original', mode='local_joint_spike'):
        return run(self.db, op='retest', id=f'rt-{at}', action=action, site='S',
                   config=config, mode=mode, receiver='rcvr',
                   position=position, psu_on=True, carrier_on=True,
                   errors=errors, baseline=0, instrument=instrument,
                   calibrated_until=calibrated_until, local_neighbor=True,
                   local_customer=True, at=at)

    def test_in_place_branch_delivers_with_matching_signatures(self):
        self.do_in_place()
        self.assertEqual(self.passing_retest()['decision'], 'retest_passed')
        run(self.db, op='neighbor', id='n', action='ground', site='S',
            retest='rt-20', decision='accepted', signer='neighbor',
            position='neighbor-original', at=21)
        run(self.db, op='customer', id='c', action='ground', site='S',
            retest='rt-20', capacity_mbps=800, latency_ms=18, uplink='up',
            signer='customer', at=22)
        run(self.db, op='submit', id='sub', action='ground', site='S',
            config='c3', position='neighbor-original', body='evidence', at=23)
        report = run(self.db, op='resolution', site='S')
        self.assertEqual(report['delivery']['state'], 'delivered')
        self.assertEqual(report['delivery']['branch'], 'in_place')
        same = (report['branches']['in_place']['retest']['config']
                == report['branches']['in_place']['neighbor_receipt']['config']
                == report['branches']['in_place']['submission']['config'])
        self.assertTrue(same)
        self.assertEqual(report['neighbor_service'],
                         'accepted_at_original_position_after_retest')
        self.assertEqual(report['customer_service'], 'contracted_service_confirmed')

    def test_separation_branch_requires_both_moves(self):
        run(self.db, op='permit', id='permit-1', site='S', position='roof-1',
            issuer='regulator', at=1)
        run(self.db, op='action', id='roof', site='S',
            kind='relocate_carrier_antenna', config_before='c1',
            config_after='c2', position='roof-1', permit='permit-1', at=10)
        run(self.db, op='receiver', id='rcvr', site='S',
            position='neighbor-original', config='c2', required_errors=5,
            at=12)
        premature = self.passing_retest(action='roof', config='c2', at=20)
        self.assertEqual(premature['decision'], 'branch_actions_incomplete')
        self.assertIn('migrate_resolution', premature['missing'])
        run(self.db, op='action', id='cabinet', site='S',
            kind='migrate_resolution', config_before='c2', config_after='c3',
            cabinet_state='accepted', uplink='up', at=11)
        run(self.db, op='receiver', id='rcvr', site='S',
            position='neighbor-original', config='c3', required_errors=5,
            at=12)
        done = self.passing_retest(action='cabinet', config='c3', at=21)
        self.assertEqual(done['decision'], 'retest_passed')

    def test_customer_capacity_below_contract_is_not_silent(self):
        self.do_in_place()
        self.passing_retest()
        result = run(self.db, op='customer', id='c', action='ground', site='S',
                     retest='rt-20', capacity_mbps=400, latency_ms=18,
                     uplink='up', signer='customer', at=22)
        self.assertEqual(result['decision'], 'customer_capacity_below_contract')
        report = run(self.db, op='resolution', site='S')
        self.assertNotEqual(report['customer_service'],
                            'contracted_service_confirmed')

    def test_customer_latency_and_uplink_checked(self):
        self.do_in_place()
        self.passing_retest()
        slow = run(self.db, op='customer', id='c', action='ground', site='S',
                   retest='rt-20', capacity_mbps=800, latency_ms=25,
                   uplink='up', signer='customer', at=22)
        self.assertEqual(slow['decision'], 'customer_latency_above_contract')
        down = run(self.db, op='customer', id='c2', action='ground', site='S',
                   retest='rt-20', capacity_mbps=800, latency_ms=18,
                   uplink='down', signer='customer', at=23)
        self.assertEqual(down['decision'], 'customer_uplink_unavailable')

    def test_customer_latency_must_be_measured_not_assumed(self):
        self.do_in_place()
        self.passing_retest()
        result = run(self.db, op='customer', id='c', action='ground', site='S',
                     retest='rt-20', capacity_mbps=800, uplink='up',
                     signer='customer', at=22)
        self.assertEqual(result['decision'], 'customer_latency_unverified')

    def test_neighbor_rejection_blocks_delivery(self):
        self.do_in_place()
        self.passing_retest()
        result = run(self.db, op='neighbor', id='n', action='ground', site='S',
                     retest='rt-20', decision='rejected', signer='neighbor',
                     position='neighbor-original', at=21)
        self.assertEqual(result['decision'], 'neighbor_rejected')
        report = run(self.db, op='resolution', site='S')
        self.assertEqual(report['delivery']['state'], 'not_delivered')
        self.assertEqual(report['branches']['in_place']['state'],
                         'awaiting_neighbor_acceptance')

    def test_neighbor_acceptance_requires_passing_retest(self):
        self.do_in_place()
        failing = run(self.db, op='retest', id='rt', action='ground', site='S',
                      config='c3', mode='local_joint_spike', receiver='rcvr',
                      position='neighbor-original', psu_on=True, carrier_on=True,
                      errors=50, baseline=0, instrument='probe-A',
                      calibrated_until=100, local_neighbor=True,
                      local_customer=True, at=20)
        self.assertEqual(failing['decision'], 'retest_failed')
        result = run(self.db, op='neighbor', id='n', action='ground', site='S',
                     retest='rt', decision='accepted', signer='neighbor',
                     position='neighbor-original', at=21)
        self.assertEqual(result['decision'], 'retest_not_passed')

    def test_neighbor_position_must_match_own_acceptance_point(self):
        self.do_in_place()
        self.passing_retest()
        result = run(self.db, op='neighbor', id='n', action='ground', site='S',
                     retest='rt-20', decision='accepted', signer='neighbor',
                     position='somewhere-else', at=21)
        self.assertEqual(result['decision'], 'measurement_point_mismatch')

    def test_retest_requires_calibration(self):
        self.do_in_place()
        expired = self.passing_retest(calibrated_until=15)
        self.assertEqual(expired['decision'], 'instrument_calibration_expired')
        unverified = run(self.db, op='retest', id='rt-x', action='ground',
                         site='S', config='c3', mode='local_joint_spike',
                         receiver='rcvr', position='neighbor-original',
                         psu_on=True, carrier_on=True, errors=1, baseline=0,
                         instrument=None, calibrated_until=None,
                         local_neighbor=True, local_customer=True, at=20)
        self.assertEqual(unverified['decision'], 'instrument_calibration_unverified')

    def test_full_shutdown_matrix_is_rejected(self):
        self.do_in_place()
        result = run(self.db, op='retest', id='rt', action='ground', site='S',
                     config='c3', mode='full_shutdown_matrix', receiver='rcvr',
                     position='neighbor-original', psu_on=False,
                     carrier_on=False, errors=0, baseline=0,
                     instrument='probe-A', calibrated_until=100,
                     local_neighbor=True, local_customer=True, at=20)
        self.assertEqual(result['decision'], 'verification_interrupts_both_parties')

    def test_joint_spike_requires_both_devices_local(self):
        self.do_in_place()
        off = run(self.db, op='retest', id='rt', action='ground', site='S',
                  config='c3', mode='local_joint_spike', receiver='rcvr',
                  position='neighbor-original', psu_on=False, carrier_on=True,
                  errors=1, baseline=0, instrument='probe-A',
                  calibrated_until=100, local_neighbor=True,
                  local_customer=True, at=20)
        self.assertEqual(off['decision'], 'joint_spike_requires_both_devices')
        remote = run(self.db, op='retest', id='rt2', action='ground', site='S',
                     config='c3', mode='local_joint_spike', receiver='rcvr',
                     position='neighbor-original', psu_on=True, carrier_on=True,
                     errors=1, baseline=0, instrument='probe-A',
                     calibrated_until=100, local_neighbor=False,
                     local_customer=True, at=21)
        self.assertEqual(remote['decision'], 'joint_spike_requires_local_service')

    def test_regulator_submission_must_match_measured_config(self):
        self.do_in_place()
        self.passing_retest()
        run(self.db, op='neighbor', id='n', action='ground', site='S',
            retest='rt-20', decision='accepted', signer='neighbor',
            position='neighbor-original', at=21)
        run(self.db, op='customer', id='c', action='ground', site='S',
            retest='rt-20', capacity_mbps=800, latency_ms=18, uplink='up',
            signer='customer', at=21)
        wrong = run(self.db, op='submit', id='sub', action='ground', site='S',
                    config='c9', position='neighbor-original', body='x', at=23)
        self.assertEqual(wrong['decision'], 'submission_config_mismatch')
        wrong_point = run(self.db, op='submit', id='sub2', action='ground',
                          site='S', config='c3', position='elsewhere',
                          body='x', at=24)
        self.assertEqual(wrong_point['decision'], 'submission_config_mismatch')
        # The accepted receipt above is the very evidence a submission needs;
        # once it exists, filing is allowed, so the order matters.
        filed = run(self.db, op='submit', id='sub3', action='ground', site='S',
                    config='c3', position='neighbor-original', body='x', at=25)
        self.assertEqual(filed['decision'], 'submission_filed')

    def test_submission_without_neighbor_receipt_is_refused(self):
        self.do_in_place()
        self.passing_retest()
        no_receipt = run(self.db, op='submit', id='sub', action='ground',
                         site='S', config='c3',
                         position='neighbor-original', body='x', at=22)
        self.assertEqual(no_receipt['decision'],
                         'submission_requires_neighbor_acceptance')

    def test_submission_without_customer_receipt_is_refused(self):
        self.do_in_place()
        self.passing_retest()
        run(self.db, op='neighbor', id='n', action='ground', site='S',
            retest='rt-20', decision='accepted', signer='neighbor',
            position='neighbor-original', at=21)
        result = run(self.db, op='submit', id='sub', action='ground', site='S',
                     config='c3', position='neighbor-original', body='x',
                     at=22)
        self.assertEqual(result['decision'],
                         'submission_requires_customer_confirmation')

    def test_regulator_withdrawal_invalidates_release(self):
        self.do_in_place()
        self.passing_retest()
        run(self.db, op='neighbor', id='n', action='ground', site='S',
            retest='rt-20', decision='accepted', signer='neighbor',
            position='neighbor-original', at=21)
        run(self.db, op='customer', id='c', action='ground', site='S',
            retest='rt-20', capacity_mbps=800, latency_ms=18, uplink='up',
            signer='customer', at=22)
        run(self.db, op='submit', id='sub', action='ground', site='S',
            config='c3', position='neighbor-original', body='x', at=23)
        self.assertEqual(run(self.db, op='resolution', site='S')['delivery']['state'],
                         'delivered')
        result = run(self.db, op='regulator_withdraw', id='wd',
                     submission='sub', at=24)
        self.assertEqual(result['decision'], 'submission_withdrawn')
        report = run(self.db, op='resolution', site='S')
        self.assertEqual(report['delivery']['state'], 'not_delivered')
        self.assertEqual(report['branches']['in_place']['state'],
                         'awaiting_regulator_submission')
        self.assertIn('c3', {w['config'] for w in report['windows']})

    def test_reintroducing_old_psu_invalidates_old_release(self):
        self.do_in_place()
        self.passing_retest()
        run(self.db, op='neighbor', id='n', action='ground', site='S',
            retest='rt-20', decision='accepted', signer='neighbor',
            position='neighbor-original', at=21)
        run(self.db, op='customer', id='c', action='ground', site='S',
            retest='rt-20', capacity_mbps=800, latency_ms=18, uplink='up',
            signer='customer', at=22)
        run(self.db, op='submit', id='sub', action='ground', site='S',
            config='c3', position='neighbor-original', body='x', at=23)
        run(self.db, op='action', id='old-psu', site='S', kind='revert_psu',
            branch='in_place', config_before='c3', config_after='c1-again',
            at=30)
        report = run(self.db, op='resolution', site='S')
        self.assertEqual(report['delivery']['state'], 'not_delivered')
        self.assertEqual(report['branches']['in_place']['state'], 'rolled_back')
        self.assertIn('sub', [s['id'] for s in report['invalidated_submissions']])
        self.assertIn('n', [r['id'] for r in report['invalidated_receipts']])

    def test_empty_window_is_reported_as_unverified(self):
        self.do_in_place()
        report = run(self.db, op='resolution', site='S')
        self.assertEqual(report['delivery']['state'], 'not_delivered')
        self.assertEqual(report['branches']['in_place']['state'], 'awaiting_retest')
        for window in report['windows']:
            self.assertEqual(window['state'], 'unverified')
        self.assertEqual(report['neighbor_service'], 'unverified')


class BranchTradeoff(Base):
    def setUp(self):
        super().setUp()
        self.site()
        self.receiver()

    def deliver(self, branch, action, position=None):
        run(self.db, op='retest', id=f'rt-{branch}', action=action, site='S',
            config='c3', mode='local_joint_spike', receiver='rcvr',
            position='neighbor-original', psu_on=True, carrier_on=True,
            errors=1, baseline=0, instrument='probe-A', calibrated_until=100,
            local_neighbor=True, local_customer=True, at=40)
        run(self.db, op='neighbor', id=f'n-{branch}', action=action, site='S',
            retest=f'rt-{branch}', decision='accepted', signer='neighbor',
            position='neighbor-original', at=41)
        run(self.db, op='customer', id=f'c-{branch}', action=action, site='S',
            retest=f'rt-{branch}', capacity_mbps=800, latency_ms=18,
            uplink='up', signer='customer', at=42)
        run(self.db, op='submit', id=f's-{branch}', action=action, site='S',
            config='c3', position='neighbor-original', body='x', at=43)

    def test_both_branches_reachable_and_reported_separately(self):
        run(self.db, op='action', id='filter1', site='S', kind='psu_filter',
            config_before='c1', config_after='c2', at=10)
        run(self.db, op='action', id='ground', site='S', kind='bridge_ground',
            config_before='c2', config_after='c3', at=11)
        run(self.db, op='permit', id='p', site='S', position='roof-1',
            issuer='regulator', at=1)
        run(self.db, op='action', id='roof', site='S',
            kind='relocate_carrier_antenna', config_before='c3',
            config_after='c4', position='roof-1', permit='p', at=12)
        run(self.db, op='action', id='cabinet', site='S',
            kind='migrate_resolution', config_before='c4', config_after='c5',
            cabinet_state='accepted', uplink='up', at=13)
        run(self.db, op='receiver', id='rcvr', site='S',
            position='neighbor-original', config='c5', required_errors=5,
            at=14)
        report = run(self.db, op='resolution', site='S')
        in_place = report['branches']['in_place']
        separation = report['branches']['separation']
        self.assertEqual(in_place['missing_actions'], [])
        self.assertEqual(separation['missing_actions'], [])
        # Neither is delivered: separation has no retest, in_place's last retest
        # belongs to c5 but the in_place branch has not been signed either.
        self.assertEqual(report['delivery']['state'], 'not_delivered')
        self.assertNotEqual(in_place['differences'], separation['differences'])
        self.assertIn('customer_latency', separation['differences'])
        self.assertIn('responsibility', separation['differences'])

    def test_shared_ground_survives_filter_so_ground_branch_still_needed(self):
        run(self.db, op='action', id='filter1', site='S', kind='psu_filter',
            config_before='c1', config_after='c2', at=10)
        run(self.db, op='receiver', id='rcvr', site='S',
            position='neighbor-original', config='c2', required_errors=5,
            at=11)
        filtered_only = run(self.db, op='retest', id='rt', action='filter1',
                            site='S', config='c2', mode='local_joint_spike',
                            receiver='rcvr', position='neighbor-original',
                            psu_on=True, carrier_on=True, errors=60, baseline=0,
                            instrument='probe-A', calibrated_until=100,
                            local_neighbor=True, local_customer=True, at=20)
        self.assertEqual(filtered_only['decision'],
                         'branch_actions_incomplete')
        self.assertIn('bridge_ground', filtered_only['missing'])

    def test_antenna_move_alone_does_not_prove_psu_radiation_gone(self):
        run(self.db, op='permit', id='p', site='S', position='roof-1',
            issuer='regulator', at=1)
        run(self.db, op='action', id='roof', site='S',
            kind='relocate_carrier_antenna', config_before='c1',
            config_after='c2', position='roof-1', permit='p', at=10)
        run(self.db, op='receiver', id='rcvr', site='S',
            position='neighbor-original', config='c2', required_errors=5,
            at=11)
        result = run(self.db, op='retest', id='rt', action='roof', site='S',
                     config='c2', mode='local_joint_spike', receiver='rcvr',
                     position='neighbor-original', psu_on=True, carrier_on=True,
                     errors=1, baseline=0, instrument='probe-A',
                     calibrated_until=100, local_neighbor=True,
                     local_customer=True, at=20)
        self.assertEqual(result['decision'], 'branch_actions_incomplete')
        self.assertIn('migrate_resolution', result['missing'])


class ReceiverAcceptanceReconfig(Base):
    def test_changed_configuration_requires_new_receiver_acceptance(self):
        self.site()
        self.receiver(config='c1')
        run(self.db, op='action', id='a', site='S', kind='psu_filter',
            config_before='c1', config_after='c2', at=10)
        stale = run(self.db, op='retest', id='rt', action='a', site='S',
                    config='c2', mode='local_joint_spike', receiver='rcvr',
                    position='neighbor-original', psu_on=True, carrier_on=True,
                    errors=1, baseline=0, instrument='probe-A',
                    calibrated_until=100, local_neighbor=True,
                    local_customer=True, at=20)
        self.assertEqual(stale['decision'], 'receiver_acceptance_config_stale')
        run(self.db, op='action', id='g', site='S', kind='bridge_ground',
            config_before='c2', config_after='c3', at=20)
        run(self.db, op='receiver', id='rcvr', site='S',
            position='neighbor-original', config='c3', required_errors=5, at=21)
        ok = run(self.db, op='retest', id='rt2', action='g', site='S',
                 config='c3', mode='local_joint_spike', receiver='rcvr',
                 position='neighbor-original', psu_on=True, carrier_on=True,
                 errors=1, baseline=0, instrument='probe-A',
                 calibrated_until=100, local_neighbor=True,
                 local_customer=True, at=22)
        self.assertEqual(ok['decision'], 'retest_passed')

    def test_receiver_cannot_move_its_acceptance_point(self):
        self.site()
        self.receiver(config='c1')
        moved = run(self.db, op='receiver', id='rcvr', site='S',
                    position='far-field', config='c2', required_errors=5, at=2)
        self.assertEqual(moved['decision'], 'receiver_position_changed')
        self.assertEqual(moved['original_position'], 'neighbor-original')

    def test_stale_receiver_registration_is_rejected(self):
        self.site()
        self.receiver(config='c1')
        stale = run(self.db, op='receiver', id='rcvr', site='S',
                    position='neighbor-original', config='c0',
                    required_errors=5, at=0)
        self.assertEqual(stale['decision'], 'stale_receiver')


class InputGuards(Base):
    def setUp(self):
        super().setUp()
        self.site()
        self.receiver()

    def test_unknown_site_and_branch_mismatch(self):
        self.assertEqual(run(self.db, op='resolution', site='missing')['decision'],
                         'unknown_site')
        bad = run(self.db, op='action', id='a', site='S', kind='psu_filter',
                  branch='separation', config_before='c1', config_after='c2',
                  at=10)
        self.assertEqual(bad['decision'], 'action_branch_mismatch')

    def test_stale_and_reused_configuration(self):
        run(self.db, op='action', id='a', site='S', kind='psu_filter',
            config_before='c1', config_after='c2', at=20)
        stale = run(self.db, op='action', id='b', site='S', kind='bridge_ground',
                    config_before='c2', config_after='c3', at=10)
        self.assertEqual(stale['decision'], 'stale_action')
        same = run(self.db, op='action', id='c', site='S', kind='bridge_ground',
                   config_before='c2', config_after='c2', at=21)
        self.assertEqual(same['decision'], 'no_configuration_change')

    def test_action_without_time_is_refused(self):
        result = run(self.db, op='action', id='a', site='S',
                     kind='psu_filter', config_before='c1',
                     config_after='c2')
        self.assertEqual(result['decision'], 'action_time_required')

    def test_event_retry_is_idempotent(self):
        payload = dict(event_id='same', op='action', id='a', site='S',
                       kind='psu_filter', config_before='c1',
                       config_after='c2', at=10)
        first = rf_resolution.run(self.db, payload)
        self.assertEqual(rf_resolution.run(self.db, payload), first)
        conflicting = dict(payload, config_after='c9')
        self.assertEqual(rf_resolution.run(self.db, conflicting)['decision'],
                         'event_identity_conflict')

    def test_spectrum_never_attributes(self):
        result = run(self.db, op='spectrum', id='sp', site='S', config='c1',
                     frequency_khz=30000, peak_mv=90, tracks='carrier_transmit',
                     at=10)
        self.assertEqual(result['attribution'], 'not_from_spectrum')

    def test_retest_cannot_predate_its_action(self):
        run(self.db, op='action', id='a', site='S', kind='psu_filter',
            config_before='c1', config_after='c2', at=20)
        early = run(self.db, op='retest', id='rt', action='a', site='S',
                    config='c2', mode='local_joint_spike', receiver='rcvr',
                    position='neighbor-original', psu_on=True, carrier_on=True,
                    errors=1, baseline=0, instrument='probe-A',
                    calibrated_until=100, local_neighbor=True,
                    local_customer=True, at=10)
        self.assertEqual(early['decision'], 'retest_before_action')

    def test_signatures_need_a_named_signer(self):
        run(self.db, op='action', id='a', site='S', kind='psu_filter',
            config_before='c1', config_after='c2', at=20)
        run(self.db, op='action', id='g', site='S', kind='bridge_ground',
            config_before='c2', config_after='c3', at=21)
        run(self.db, op='receiver', id='rcvr', site='S',
            position='neighbor-original', config='c3', required_errors=5,
            at=21)
        run(self.db, op='retest', id='rt', action='g', site='S', config='c3',
            mode='local_joint_spike', receiver='rcvr',
            position='neighbor-original', psu_on=True, carrier_on=True,
            errors=1, baseline=0, instrument='probe-A', calibrated_until=100,
            local_neighbor=True, local_customer=True, at=22)
        unsigned = run(self.db, op='neighbor', id='n', action='g', site='S',
                       retest='rt', decision='accepted',
                       position='neighbor-original', at=23)
        self.assertEqual(unsigned['decision'], 'signer_required')

    def test_diagnosis_rejects_mixed_load_or_configuration(self):
        self.trial(True, True, 100, 10)
        self.trial(True, False, 60, 11, load_pct=40)
        self.trial(False, True, 65, 12)
        self.trial(False, False, 0, 13)
        self.assertEqual(self.diagnose()['decision'], 'trial_load_mismatch')
        for i, (psu, carrier, errors) in enumerate(
                ((1, 1, 100), (1, 0, 60), (0, 1, 65), (0, 0, 0)), start=14):
            self.trial(bool(psu), bool(carrier), errors, i, config='other')
        self.assertEqual(self.diagnose(experiment='E', at=30)['decision'],
                         'trial_configuration_mismatch')

    def test_trial_from_another_site_is_not_borrowed(self):
        self.trial(True, True, 100, 10)
        self.trial(True, False, 60, 11)
        self.trial(False, True, 65, 12)
        run(self.db, op='trial', id='foreign', site='ELSEWHERE',
            experiment='E', config='c1', receiver='rcvr', psu_on=False,
            carrier_on=False, load_pct=90, baseline=5, errors=0, at=13)
        self.assertEqual(self.diagnose()['decision'], 'experiment_incomplete')

    def test_rollback_action_cannot_be_signed_or_submitted(self):
        run(self.db, op='action', id='a', site='S', kind='psu_filter',
            config_before='c1', config_after='c2', at=20)
        run(self.db, op='action', id='rb', site='S', kind='revert_psu',
            branch='in_place', config_before='c2', config_after='c1b', at=21)
        signed = run(self.db, op='neighbor', id='n', action='rb', site='S',
                     retest='rt', decision='accepted', signer='x',
                     position='neighbor-original', at=22)
        self.assertEqual(signed['decision'], 'rollback_action_not_signable')

    def test_contract_identity_cannot_be_silently_reduced(self):
        reduced = run(self.db, op='site', site='S', neighbor_site='N',
                      neighbor_capacity_mbps=500, customer_capacity_mbps=100,
                      customer_latency_ms=20)
        self.assertEqual(reduced['decision'], 'site_contract_identity_conflict')

    def test_sample_bound_to_config_keeps_an_unverified_window(self):
        run(self.db, op='sample', id='s1', site='S', frequency_khz=30000,
            at=10, field_mv=10, instrument='probe-A', bandwidth_khz=200,
            calibrated_until=100, antenna='sector-3', point='neighbor-original',
            load_pct=90, config='c1')
        report = run(self.db, op='resolution', site='S')
        self.assertEqual([(w['config'], w['state']) for w in report['windows']],
                         [('c1', 'unverified')])


class NormalAndFailureFixtures(unittest.TestCase):
    def load(self, name):
        from pathlib import Path
        return json.loads((Path('fixtures') / name).read_text(encoding='utf-8'))

    def test_normal_fixture_delivers_after_action_and_signoff(self):
        db = connect(':memory:')
        decisions = [rf_resolution.run(db, x) for x in self.load('rf-normal.json')]
        self.assertEqual(decisions[4]['decision'], 'blocked')
        self.assertEqual(decisions[10]['decision'], 'diagnosed')
        self.assertEqual(decisions[-1]['decision'], 'resolution_reported')
        self.assertEqual(decisions[-1]['delivery']['state'], 'delivered')
        self.assertEqual(decisions[-1]['delivery']['branch'], 'in_place')
        self.assertIsNone(decisions[-1]['static_label'])
        db.close()

    def test_failure_fixture_does_not_deliver_on_filter_alone(self):
        db = connect(':memory:')
        decisions = [rf_resolution.run(db, x) for x in self.load('rf-failure.json')]
        self.assertEqual(decisions[-2]['decision'], 'retest_failed')
        report = decisions[-1]
        self.assertEqual(report['delivery']['state'], 'not_delivered')
        self.assertEqual(report['neighbor_service'], 'unverified')
        self.assertIsNone(report['static_label'])
        self.assertEqual(report['branches']['in_place']['state'], 'awaiting_retest')
        db.close()


if __name__ == '__main__':
    unittest.main()
