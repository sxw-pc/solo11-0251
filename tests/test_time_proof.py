import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cloudcourt import time_proof
from cloudcourt.clock_reference import observe
from cloudcourt.store import connect, one, many
from cloudcourt.time_attestation import provisional


class TimeProofTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = connect(str(Path(self.tmp.name) / 'db.sqlite'))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def op(self, event_id, name, **kw):
        return time_proof.run(self.db, dict({'event_id': event_id, 'op': name}, **kw))

    def evidence(self, event_id, **kw):
        return self.op(event_id, 'evidence', **kw)

    def issue(self, event_id, **kw):
        return self.op(event_id, 'issue', **kw)

    def deliver(self, event_id, **kw):
        return self.op(event_id, 'deliver', **kw)

    def ack(self, event_id, delivery, at):
        return self.op(event_id, 'ack', id=delivery, at=at)

    def spoofed_pair(self, site, upstream):
        for antenna in ('ant-1', 'ant-2'):
            self.evidence(f'{site}-{antenna}', id=f'{site}-{antenna}', site=site,
                          chain='gnss-l1', upstream=upstream, antenna=antenna,
                          direct=True, observed_local=9000, offset_ms=-5000,
                          uncertainty_ms=2, calibration='gps-cal')

    def oscillator(self, event_id, site, evidence_id='ox', observed=8000, drift=0.001):
        return self.evidence(event_id, id=evidence_id, site=site, chain='local-ocxo',
                             upstream='self', direct=True, observed_local=observed,
                             offset_ms=0, uncertainty_ms=1, calibration='cal-ox',
                             calibration_uncertainty_ms=1, drift_ppm=drift)

    def ground(self, event_id, site, evidence_id='g', observed=9500):
        return self.evidence(event_id, id=evidence_id, site=site, chain='ptp-ground',
                             upstream=f'terrestrial-{site}', observed_local=observed,
                             offset_ms=0, uncertainty_ms=1, calibration='cal-g',
                             calibration_uncertainty_ms=1)

    def test_shared_upstream_antennas_count_once(self):
        self.spoofed_pair('s1', 'splitter-1/gps')
        self.evidence('s1-g', id='g1', site='s1', chain='ptp-ground',
                      upstream='terrestrial-1', direct=True, observed_local=9000,
                      offset_ms=0, uncertainty_ms=2, calibration='ground-cal')
        groups = time_proof.evidence_groups(self.db, 's1')
        self.assertEqual(2, len(groups))
        self.assertEqual(['s1-ant-1', 's1-ant-2'], sorted(groups['splitter-1/gps']))
        # Two antennas on one splitter are one vote: the merge refuses the
        # conflict instead of letting the pair outvote the ground link.
        r = self.issue('s1-i1', id='p1', site='s1', issuer='attester',
                       event_digest='d1', local_ms=10000, at=10000)
        self.assertEqual('source_conflict', r['decision'])
        self.assertEqual([4998, 5002], r['intervals']['splitter-1/gps'])
        self.assertEqual([9998, 10002], r['intervals']['terrestrial-1'])
        # Distrusting the shared upstream retires both antennas at once.
        r = self.op('s1-d', 'distrust', upstream='splitter-1/gps')
        self.assertEqual('upstream_distrusted', r['decision'])
        self.assertEqual(2, r['count'])
        r = self.issue('s1-i2', id='p2', site='s1', issuer='attester',
                       event_digest='d1', local_ms=10000, at=10001)
        self.assertEqual('proof_issued', r['decision'])
        self.assertEqual((9998, 10002), (r['lower_ms'], r['upper_ms']))

    def test_oscillator_drift_widens_holdover_intervals(self):
        self.oscillator('s2-ox', 's2', observed=0)
        r1 = self.issue('s2-i1', id='p1', site='s2', issuer='a',
                        event_digest='d', local_ms=10000, at=10000)
        self.assertEqual('proof_issued_wide', r1['decision'])
        self.assertEqual((9988, 10012), (r1['lower_ms'], r1['upper_ms']))
        r2 = self.issue('s2-i2', id='p2', site='s2', issuer='a',
                        event_digest='d', local_ms=100000, at=100000)
        # half-width is the conservative drift bound, not faked milliseconds
        self.assertEqual((99898, 100102), (r2['lower_ms'], r2['upper_ms']))
        self.assertEqual('wide', r2['service'])
        level = time_proof.service_level(self.db, 's2', 100000)
        self.assertTrue(level['wide']['available'])
        self.assertEqual(102, level['wide']['uncertainty_ms'])
        self.assertFalse(level['narrow']['available'])
        # Overlapping wide intervals: no unique order is derivable from logs.
        r3 = self.issue('s2-i3', id='p3', site='s2', issuer='a',
                        event_digest='d', local_ms=100050, at=100050)
        self.assertEqual('indeterminate', time_proof.order(self.db, 'p2', 'p3')['order'])

    def test_leap_second_evidence_required_for_timescale_merge(self):
        self.evidence('s3-gps', id='gps', site='s3', chain='gnss-l1',
                      upstream='gps-direct', direct=True, timescale='GPS',
                      observed_local=15000, offset_ms=18000, uncertainty_ms=2,
                      calibration='gps-cal')
        self.evidence('s3-ug', id='ug', site='s3', chain='ptp-ground',
                      upstream='terrestrial-9', observed_local=15000, offset_ms=0,
                      uncertainty_ms=1, calibration='ground-cal',
                      calibration_uncertainty_ms=1,
                      transport={'min_ms': 2, 'max_ms': 4, 'rtt_ms': 6})
        r = self.issue('s3-i1', id='p1', site='s3', issuer='a',
                       event_digest='d', local_ms=20000, at=20000)
        self.assertEqual('leap_evidence_missing', r['decision'])
        self.op('s3-leap', 'leap', id='leap-2026', from_timescale='GPS',
                shift_ms=18000, effective_local=10000)
        r = self.issue('s3-i2', id='p2', site='s3', issuer='a',
                       event_digest='d', local_ms=20000, at=20000)
        self.assertEqual('proof_issued', r['decision'])
        self.assertEqual((19998, 20002), (r['lower_ms'], r['upper_ms']))
        basis = json.loads(one(self.db, 'SELECT basis FROM time_proofs WHERE id=?', ('p2',))['basis'])
        hop = [h for g in basis['groups'] for h in g if h['evidence'] == 'gps'][0]
        self.assertEqual('leap-2026', hop['leap_table'])
        self.assertEqual(18000, hop['leap_shift_ms'])
        self.assertTrue(time_proof.verify(self.db, 'p2')['valid'])
        # An event before the table's applicability is still refused.
        r = self.issue('s3-i3', id='p3', site='s3', issuer='a',
                       event_digest='d', local_ms=5000, at=5000)
        self.assertEqual('leap_evidence_missing', r['decision'])

    def test_cross_device_delay_bounds_and_ordering(self):
        self.ground('s4-g', 's4', observed=25000)
        self.op('s4-gc', 'calibrate', id='g',
                transport={'min_ms': 2, 'max_ms': 4, 'rtt_ms': 6}, at=25001)
        self.evidence('s4-l1', id='link-1', site='s4', chain='device-link',
                      upstream='lan-1', observed_local=25000, offset_ms=5,
                      uncertainty_ms=1, calibration='cal-l1',
                      transport={'min_ms': 2, 'max_ms': 10, 'rtt_ms': 12})
        self.evidence('s4-l2', id='link-2', site='s4', chain='device-link',
                      upstream='lan-2', observed_local=25000, offset_ms=-5,
                      uncertainty_ms=1, calibration='cal-l2',
                      transport={'min_ms': 2, 'max_ms': 10, 'rtt_ms': 12})
        r1 = self.issue('s4-i1', id='dev-p1', site='s4', issuer='a',
                        event_digest='e1', local_ms=30000, via='link-1', at=30001)
        self.assertEqual((29997, 30013), (r1['lower_ms'], r1['upper_ms']))
        r2 = self.issue('s4-i2', id='dev-p2', site='s4', issuer='a',
                        event_digest='e2', local_ms=30010, via='link-2', at=30002)
        self.assertEqual((29997, 30013), (r2['lower_ms'], r2['upper_ms']))
        # Receive order is known (dev-p1 stored first) but intervals overlap.
        self.assertEqual('indeterminate', time_proof.order(self.db, 'dev-p1', 'dev-p2')['order'])
        basis = json.loads(one(self.db, "SELECT basis FROM time_proofs WHERE id='dev-p1'")['basis'])
        self.assertEqual({'min_ms': 2, 'max_ms': 10, 'rtt_ms': 12}, basis['via']['transport'])
        # Tight links decide the order even when proofs are stored in reverse.
        self.evidence('s4-l3', id='link-3', site='s4', chain='device-link',
                      upstream='lan-3', observed_local=25000, offset_ms=5,
                      uncertainty_ms=0, calibration='cal-l3',
                      transport={'min_ms': 2, 'max_ms': 3, 'rtt_ms': 5})
        self.evidence('s4-l4', id='link-4', site='s4', chain='device-link',
                      upstream='lan-4', observed_local=25000, offset_ms=-5,
                      uncertainty_ms=0, calibration='cal-l4',
                      transport={'min_ms': 2, 'max_ms': 3, 'rtt_ms': 5})
        r4 = self.issue('s4-i4', id='dev-p4', site='s4', issuer='a',
                        event_digest='e4', local_ms=40020, via='link-4', at=40001)
        r3 = self.issue('s4-i3', id='dev-p3', site='s4', issuer='a',
                        event_digest='e3', local_ms=40000, via='link-3', at=40002)
        self.assertEqual((40011, 40019), (r4['lower_ms'], r4['upper_ms']))
        self.assertEqual((40001, 40009), (r3['lower_ms'], r3['upper_ms']))
        self.assertEqual('a-before-b', time_proof.order(self.db, 'dev-p3', 'dev-p4')['order'])

    def test_delivered_correction_and_offline_witness(self):
        # The spoofed pair is the only source when both proofs are issued.
        self.spoofed_pair('s5', 'splitter-1/gps')
        pa = self.issue('s5-i1', id='pa', site='s5', issuer='attester-1',
                        event_digest='event-alpha', local_ms=11000, at=11001)
        self.assertEqual((5998, 6002), (pa['lower_ms'], pa['upper_ms']))
        pb = self.issue('s5-i2', id='pb', site='s5', issuer='attester-1',
                        event_digest='event-beta', local_ms=12000, at=12001)
        self.assertEqual((6998, 7002), (pb['lower_ms'], pb['upper_ms']))
        self.deliver('s5-d1', id='d-pa-ca', proof='pa', recipient='customer-a',
                     kind='original', at=11002)
        self.deliver('s5-d2', id='d-pa-w', proof='pa', recipient='witness-w',
                     kind='original', at=11003)
        self.ack('s5-a1', 'd-pa-ca', 11004)
        self.ack('s5-a2', 'd-pa-w', 11005)
        # Incident response: oscillator cross-check and a calibrated ground
        # link both sit within 3ms of zero, exposing the -5s spoof.
        self.oscillator('s5-ox', 's5')
        self.ground('s5-g', 's5')
        r = self.issue('s5-i3', id='pc', site='s5', issuer='attester-1',
                       event_digest='event-gamma', local_ms=12500, at=12501)
        self.assertEqual('source_conflict', r['decision'])
        self.op('s5-gc', 'calibrate', id='g',
                transport={'min_ms': 4, 'max_ms': 6, 'rtt_ms': 10}, at=12502)
        r = self.op('s5-dt', 'distrust', upstream='splitter-1/gps')
        self.assertEqual(2, r['count'])
        # Correction is a new proof chained to the old one; signed content
        # of the delivered proof is never rewritten.
        before = one(self.db, 'SELECT * FROM time_proofs WHERE id=?', ('pa',))
        pa2 = self.issue('s5-i4', id='pa2', site='s5', issuer='attester-1',
                         corrects='pa', at=12503)
        self.assertEqual((10997, 11003), (pa2['lower_ms'], pa2['upper_ms']))
        after = one(self.db, 'SELECT * FROM time_proofs WHERE id=?', ('pa',))
        for col in ('issuer', 'event_digest', 'seq', 'local_ms', 'lower_ms', 'upper_ms', 'basis'):
            self.assertEqual(before[col], after[col])
        self.assertEqual('pa2', after['superseded_by'])
        # Every holder of pa is auto-notified of the correction; the offline
        # witness simply stays unacknowledged.
        self.ack('s5-a3', 'pa2:customer-a', 12504)
        r = self.op('s5-rv', 'revoke', id='pa', at=12505)
        self.assertEqual('pending', r['revocation'])
        self.assertEqual(['customer-a', 'witness-w'], r['recipients'])
        self.ack('s5-a4', 'rev:pa:customer-a', 12506)
        self.assertEqual('pending', one(self.db, "SELECT revocation FROM time_proofs WHERE id='pa'")['revocation'])
        # The system keeps showing exactly who holds which version.
        pending = time_proof.pending_deliveries(self.db)
        self.assertEqual({'pa2:witness-w', 'rev:pa:witness-w'}, {d['id'] for d in pending})
        status = time_proof.proof_status(self.db, 'pa')
        self.assertEqual(['pa', 'pa2'], status['chain'])
        receipts = {(d['recipient'], d['kind'], d['state'])
                    for v in status['versions'] for d in v['deliveries']}
        self.assertIn(('witness-w', 'original', 'acked'), receipts)
        self.assertIn(('witness-w', 'correction', 'sent'), receipts)
        self.assertIn(('witness-w', 'revocation', 'sent'), receipts)
        self.assertIn(('customer-a', 'correction', 'acked'), receipts)
        # The old signature stays verifiable as a historical artifact, but
        # its status exposes the distrusted basis and the pending revocation.
        v = time_proof.verify(self.db, 'pa')
        self.assertTrue(v['valid'])
        self.assertEqual('pa2', v['status']['superseded_by'])
        self.assertEqual('distrusted', v['status']['basis_states']['s5-ant-1'])
        # Witness comes back online: the revocation handoff completes.
        self.ack('s5-a5', 'pa2:witness-w', 13000)
        self.ack('s5-a6', 'rev:pa:witness-w', 13001)
        self.assertEqual('acked', one(self.db, "SELECT revocation FROM time_proofs WHERE id='pa'")['revocation'])
        self.assertEqual([], time_proof.pending_deliveries(self.db))
        # Corrected intervals decide the order of the two events.
        pb2 = self.issue('s5-i5', id='pb2', site='s5', issuer='attester-1',
                         corrects='pb', at=12507)
        self.assertEqual((11997, 12003), (pb2['lower_ms'], pb2['upper_ms']))
        self.assertEqual('a-before-b', time_proof.order(self.db, 'pa2', 'pb2')['order'])

    def test_undelivered_proof_blocked_from_release(self):
        self.spoofed_pair('s6', 'splitter-9/gps')
        pb = self.issue('s6-i1', id='pb', site='s6', issuer='attester-1',
                        event_digest='event-beta', local_ms=12000, at=12001)
        self.assertEqual((6998, 7002), (pb['lower_ms'], pb['upper_ms']))
        self.oscillator('s6-ox', 's6')
        self.ground('s6-g', 's6')
        self.op('s6-gc', 'calibrate', id='g',
                transport={'min_ms': 4, 'max_ms': 6, 'rtt_ms': 10}, at=12502)
        self.op('s6-dt', 'distrust', upstream='splitter-9/gps')
        # The wrong proof never left the building and now it never will.
        r = self.deliver('s6-d1', id='d1', proof='pb', recipient='customer-b',
                         kind='original', at=12503)
        self.assertEqual('release_blocked', r['decision'])
        self.assertEqual([], many(self.db, "SELECT * FROM proof_deliveries WHERE proof='pb'"))
        pb2 = self.issue('s6-i2', id='pb2', site='s6', issuer='attester-1',
                         corrects='pb', at=12504)
        self.assertEqual((11997, 12003), (pb2['lower_ms'], pb2['upper_ms']))
        r = self.deliver('s6-d2', id='d2', proof='pb2', recipient='customer-b',
                         kind='original', at=12505)
        self.assertEqual('delivered', r['decision'])
        r = self.deliver('s6-d3', id='d3', proof='pb', recipient='customer-b',
                         kind='original', at=12506)
        self.assertEqual('release_blocked', r['decision'])
        # Revoking a proof with no holders closes vacuously.
        r = self.op('s6-rv', 'revoke', id='pb', at=12507)
        self.assertEqual('acked', r['revocation'])
        self.assertEqual([], r['recipients'])

    def test_late_calibration_service_levels_and_repeated_correction(self):
        self.oscillator('s7-ox', 's7', observed=1000)
        level = time_proof.service_level(self.db, 's7', 51000)
        self.assertTrue(level['wide']['available'])
        self.assertEqual(52, level['wide']['uncertainty_ms'])
        self.assertFalse(level['narrow']['available'])
        pw = self.issue('s7-i1', id='pw', site='s7', issuer='a',
                        event_digest='d', local_ms=50000, at=50000)
        self.assertEqual('proof_issued_wide', pw['decision'])
        self.assertEqual((49949, 50051), (pw['lower_ms'], pw['upper_ms']))
        self.deliver('s7-d1', id='pw-c', proof='pw', recipient='customer-c',
                     kind='original', at=50001)
        # Ground link connected but round-trip calibration unfinished:
        # narrow stays unavailable and issuance keeps riding the oscillator.
        self.ground('s7-g', 's7', observed=49000)
        level = time_proof.service_level(self.db, 's7', 51000)
        self.assertFalse(level['narrow']['available'])
        self.assertEqual('calibration_pending', level['narrow']['reason'])
        waiting = self.issue('s7-i2', id='p-wait', site='s7', issuer='a',
                             event_digest='d', local_ms=50500, at=50500)
        self.assertEqual('proof_issued_wide', waiting['decision'])
        # Late calibration completes: narrow resumes, old proofs unchanged.
        self.op('s7-gc', 'calibrate', id='g',
                transport={'min_ms': 2, 'max_ms': 4, 'rtt_ms': 6}, at=51001)
        level = time_proof.service_level(self.db, 's7', 51000)
        self.assertTrue(level['narrow']['available'])
        self.assertTrue(level['wide']['available'])
        pn = self.issue('s7-i3', id='pn', site='s7', issuer='a',
                        event_digest='d', local_ms=52000, at=52000)
        self.assertEqual('proof_issued', pn['decision'])
        self.assertEqual((51997, 52003), (pn['lower_ms'], pn['upper_ms']))
        pw2 = self.issue('s7-i4', id='pw2', site='s7', issuer='a',
                         corrects='pw', at=51002)
        self.assertEqual((49997, 50003), (pw2['lower_ms'], pw2['upper_ms']))
        # The superseded original can no longer be released as current.
        r = self.deliver('s7-d2', id='pw-c2', proof='pw', recipient='customer-d',
                         kind='original', at=51003)
        self.assertEqual('stale_version', r['decision'])
        # Repeated corrections: old heads refuse, no-change is redundant.
        r = self.issue('s7-i5', id='pw2x', site='s7', issuer='a',
                       corrects='pw', at=51004)
        self.assertEqual('already_superseded', r['decision'])
        r = self.issue('s7-i6', id='pw3', site='s7', issuer='a',
                       corrects='pw2', at=51005)
        self.assertEqual('redundant_correction', r['decision'])
        # A genuinely better source yields a real second correction, and the
        # holder of the first version is notified of each new head.
        self.evidence('s7-g2', id='g2', site='s7', chain='ptp-ground-2',
                      upstream='terrestrial-8', observed_local=48000, offset_ms=0,
                      uncertainty_ms=0, calibration='cal-g2',
                      transport={'min_ms': 2, 'max_ms': 3, 'rtt_ms': 5})
        pw3 = self.issue('s7-i7', id='pw3b', site='s7', issuer='a',
                         corrects='pw2', at=51006)
        self.assertEqual((49999, 50001), (pw3['lower_ms'], pw3['upper_ms']))
        status = time_proof.proof_status(self.db, 'pw')
        self.assertEqual(['pw', 'pw2', 'pw3b'], status['chain'])
        notices = {(d['recipient'], d['kind']) for v in status['versions'] for d in v['deliveries']}
        self.assertIn(('customer-c', 'original'), notices)
        self.assertIn(('customer-c', 'correction'), notices)

    def test_verify_rejects_forged_precision_and_tampered_basis(self):
        self.oscillator('s8-ox', 's8', observed=0)
        self.issue('s8-i1', id='p1', site='s8', issuer='a',
                   event_digest='d', local_ms=100000, at=100000)
        self.assertTrue(time_proof.verify(self.db, 'p1')['valid'])
        row = one(self.db, 'SELECT * FROM time_proofs WHERE id=?', ('p1',))
        # A forged proof that claims millisecond precision on the same basis.
        self.db.execute('INSERT INTO time_proofs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                        ('fake', 's8', 'a', None, 'd', 99, 100000, 100099, 100101,
                         'wide', row['basis'], None, None, 'none'))
        v = time_proof.verify(self.db, 'fake')
        self.assertFalse(v['valid'])
        self.assertIn('interval_mismatch', v['reasons'])
        # A tampered basis whose recorded uncertainty was shrunk to fit.
        basis = json.loads(row['basis'])
        basis['groups'][0][0]['total_uncertainty_ms'] = 0
        self.db.execute('INSERT INTO time_proofs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                        ('fake2', 's8', 'a', None, 'd', 100, 100000, 99900, 100100,
                         'wide', json.dumps(basis, sort_keys=True), None, None, 'none'))
        v = time_proof.verify(self.db, 'fake2')
        self.assertFalse(v['valid'])
        self.assertIn('basis_tampered', v['reasons'])

    def test_provisional_attestation_gets_verifiable_correction(self):
        # Recreate the seed incident: the latest bad reference writes 12000 as 7000.
        observe(self.db, 'R1', 'site-1', 'gps-1', 10, 0, 2, 100)
        observe(self.db, 'R2', 'site-1', 'gps-2', 11, -5000, 2, 100)
        self.assertEqual(7000, provisional(self.db, 'A1', 'site-1', 'permit', 12000))
        # Legacy rows carry no chain, calibration or upstream: not evidence.
        r = self.issue('t1', id='fix-1', site='site-1', issuer='attester',
                       event_ref='A1', local_ms=12000, at=12001)
        self.assertEqual('no_time_evidence', r['decision'])
        self.oscillator('t2', 'site-1', evidence_id='ox', observed=5, drift=0.0)
        r = self.issue('t3', id='fix-2', site='site-1', issuer='attester',
                       event_ref='A1', local_ms=12000, at=12002)
        self.assertEqual('proof_issued_wide', r['decision'])
        self.assertEqual((11998, 12002), (r['lower_ms'], r['upper_ms']))
        # The provisional record is history and stays untouched; the bad
        # claim simply falls outside the verifiable bound.
        claimed = one(self.db, "SELECT claimed_ms FROM time_attestations WHERE id='A1'")['claimed_ms']
        self.assertEqual(7000, claimed)
        self.assertFalse(r['lower_ms'] <= claimed <= r['upper_ms'])
        proof = one(self.db, "SELECT * FROM time_proofs WHERE id='fix-2'")
        original = one(self.db, "SELECT * FROM time_attestations WHERE id='A1'")
        expect = hashlib.sha256(json.dumps(original, sort_keys=True).encode()).hexdigest()
        self.assertEqual(expect, proof['event_digest'])
        self.assertTrue(time_proof.verify(self.db, 'fix-2')['valid'])


if __name__ == '__main__':
    unittest.main()
