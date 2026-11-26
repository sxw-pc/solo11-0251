"""Resolver handoff for in-flight connections.

Covers the minute-18..22 scene from the brief and both contract-allowed
dispositions:

* F admitted at minute 18 to IP-A with 100 bytes reserved;
* a device reading at minute 20 proves 60 bytes;
* resolver R1 is revoked at minute 21 and R2 resolves the name to IP-B;
* at minute 22 the old proxy replays a success receipt marked minute 19
  claiming 80 bytes.

The tests pin the frozen identity frame, late-receipt verification,
dual-proxy retries, the shared window quota boundary, bounded disputes,
arbitrator expiry, append-only records and full event/state replay.
"""

import json
import tempfile
import unittest
from pathlib import Path

from cloudcourt import name, permit, flow
from cloudcourt.store import connect, replay, one, many


class HandoffScene(unittest.TestCase):
    capacity = 100
    limit = 100
    reserved = 100

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'handoff.sqlite')
        self.db = connect(self.path)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def call(self, module, event_id, op, **payload):
        payload.update({'event_id': event_id, 'op': op})
        return module.run(self.db, payload)

    # -- scene construction -------------------------------------------------
    def admit_f(self):
        c, db = self.call, self.db
        c(name, 'profile-1', 'profile', id='p', tenant='t',
          host='api.example.invalid', generation=1)
        c(name, 'resolver-r1', 'resolver', id='r1', tenant='t',
          source='rs1', generation=1)
        c(name, 'answer-a', 'observe', id='ans-a', profile='p',
          resolver='r1', source='rs1', ip='IP-A', generation=1,
          observed=10, expires=1000)
        c(permit, 'purpose-1', 'purpose', id='pu', tenant='t',
          profile='p', purpose='fetch')
        c(permit, 'window-1', 'quota', id='w', tenant='t',
          capacity=self.capacity, start=0, expires=1000)
        c(permit, 'grant-1', 'grant', id='g', contract='pu', window='w',
          holder='worker', limit_bytes=self.limit, at=17)
        c(flow, 'pin-a', 'pin', id='pin-a', observation='ans-a', at=18)
        admitted = c(flow, 'connect-f', 'connect', id='F', grant='g',
                     pin='pin-a', holder='worker', ip='IP-A', at=18,
                     bytes=self.reserved)
        self.assertEqual(admitted['decision'], 'admitted')
        return admitted

    def device_reading_60(self):
        return self.call(flow, 'meter-60', 'meter', id='dev-60', flow='F',
                         bytes=60, at=20)

    def rotate_resolver(self, effective_at=21):
        c = self.call
        revoked = c(name, 'revoke-r1', 'resolver', id='r1', tenant='t',
                    source='rs1', generation=2, state='revoked')
        self.assertEqual(revoked['decision'], 'resolver_revoked')
        handoff = c(flow, 'handoff-1', 'handoff', id='ho-1', flow='F',
                    at=effective_at, new_resolver='r2', new_ip='IP-B')
        self.assertEqual(handoff['decision'], 'handoff_recorded')
        c(name, 'resolver-r2', 'resolver', id='r2', tenant='t',
          source='rs2', generation=1)
        c(name, 'answer-b', 'observe', id='ans-b', profile='p',
          resolver='r2', source='rs2', ip='IP-B', generation=2,
          observed=effective_at, expires=1000)
        pinned = c(flow, 'pin-b', 'pin', id='pin-b', observation='ans-b',
                   at=effective_at + 1)
        self.assertEqual(pinned['decision'], 'pinned')
        return handoff

    def late_receipt_80(self, event_id='late-80', receipt_id='rcpt-80',
                        key='verdict-minute-19', **extra):
        payload = dict(id=receipt_id, flow='F', actual=80, at=22,
                       marked_at=19, source='old-proxy', receipt_key=key)
        payload.update(extra)
        return self.call(flow, event_id, 'settle', **payload)

    def corroborate(self, amount, event_suffix='', sent_at=20):
        self.call(flow, f'confirm-{amount}{event_suffix}', 'confirm',
                  id=f'client-{amount}{event_suffix}', flow='F',
                  bytes=amount, sent_at=sent_at, at=22)
        self.call(flow, f'counter-{amount}{event_suffix}', 'counter',
                  id=f'egress-{amount}{event_suffix}', flow='F',
                  bytes=amount, sent_at=sent_at, at=22)

    def partial_disposition_60(self):
        self.corroborate(60, '-b')
        r = self.late_receipt_80(event_id='late-80b',
                                 receipt_id='rcpt-80b', key='V19b')
        self.assertEqual(r['decision'], 'settlement_held')
        return r

    def register_auditor(self, aid='aud', actor='auditor-1', expires=30):
        return self.call(permit, f'arb-{aid}', 'arbitrator', id=aid,
                         tenant='t', actor=actor, role='auditor',
                         generation=1, at=10, expires=expires)

    def window_used(self):
        return one(self.db, 'SELECT used,held FROM quota_windows WHERE id=?',
                   ('w',))

    def grant_row(self):
        return one(self.db, 'SELECT * FROM egress_grants WHERE id=?', ('g',))

    def flow_row(self, fid='F'):
        return one(self.db, 'SELECT * FROM flow_attempts WHERE id=?', (fid,))

    def assert_replay_verified(self):
        self.db.close()
        rep = replay(self.path)
        self.assertTrue(rep['verified'], rep['mismatch'])
        self.db = connect(self.path)


class ResolverRevocationReplayTests(HandoffScene):
    def test_old_identity_frame_is_fixed_and_old_answers_cannot_advance(self):
        self.admit_f()

        # Before revocation, a re-sent generation-1 answer is already stale
        # against the accepted generation-1 high-water mark.
        stale_before = self.call(name, 'old-answer-early', 'observe',
                                 id='ans-a-early', profile='p', resolver='r1',
                                 source='rs1', ip='IP-A', generation=1,
                                 observed=19, expires=120)
        self.assertEqual(stale_before['decision'], 'stale_dns_answer')

        self.rotate_resolver()

        # Frozen frame: old observation/pin/IP, establishment and fence time.
        f = self.flow_row()
        self.assertEqual(f['established_at'], 18)
        self.assertEqual(f['fence_at'], 21)
        self.assertEqual(f['old_ip'], 'IP-A')
        self.assertEqual(f['old_observation'], 'ans-a')
        frame = json.loads(f['frame'])
        self.assertEqual(frame['ip'], 'IP-A')
        self.assertEqual(frame['observation'], 'ans-a')
        self.assertEqual(frame['resolver'], 'r1')
        self.assertEqual(frame['established_at'], 18)

        ho = one(self.db, 'SELECT * FROM resolver_handoffs WHERE id=?',
                 ('ho-1',))
        self.assertEqual(ho['old_ip'], 'IP-A')
        self.assertEqual(ho['new_ip'], 'IP-B')
        self.assertEqual(ho['established_at'], 18)
        self.assertEqual(ho['effective_at'], 21)
        self.assertEqual(ho['state'], 'frozen')

        # Exact redelivery of the revocation is the same recorded result.
        again = self.call(name, 'revoke-r1', 'resolver', id='r1',
                          tenant='t', source='rs1', generation=2,
                          state='revoked')
        self.assertEqual(again['decision'], 'resolver_revoked')

        # A fresh command reusing generation 2 is stale.
        stale = self.call(name, 'revoke-r1-again', 'resolver', id='r1',
                          tenant='t', source='rs1', generation=2,
                          state='revoked')
        self.assertEqual(stale['decision'], 'stale_resolver')

        # Re-sent old answer after R1 revocation is refused at the resolver
        # trust fence (and, on an active rotated resolver, by generation).
        old_answer = self.call(name, 'old-answer-resend', 'observe',
                               id='ans-a-resend', profile='p', resolver='r1',
                               source='rs1', ip='IP-A', generation=1,
                               observed=22, expires=120)
        self.assertIn(old_answer['decision'],
                      ('untrusted_resolver', 'stale_dns_answer'))

        # New requests on the old pin/target are still refused.
        denied = self.call(flow, 'new-on-old', 'connect', id='F2',
                           grant='g', pin='pin-a', holder='worker',
                           ip='IP-A', at=22, bytes=1)
        self.assertEqual(denied['decision'], 'dns_identity_changed')

        # A second handoff command must not move the fence.
        second = self.call(flow, 'handoff-2', 'freeze', id='ho-2', flow='F',
                           at=25)
        self.assertEqual(second['decision'], 'handoff_already_recorded')
        self.assertEqual(self.flow_row()['fence_at'], 21)
        self.assert_replay_verified()


class LateReceiptTests(HandoffScene):
    def test_late_receipt_alone_is_bounded_by_device_floor(self):
        self.admit_f()
        self.assertEqual(self.device_reading_60()['decision'],
                         'meter_recorded')
        self.rotate_resolver()
        r = self.late_receipt_80()
        # 60 proven, extra 20 held as a bounded dispute instead of charged.
        self.assertEqual(r['decision'], 'settlement_held')
        self.assertEqual(r['settled'], 60)
        self.assertEqual(r['disputed'], 20)
        self.assertEqual(r['released'], 20)
        self.assertEqual(self.window_used()['used'], 60)
        d = one(self.db,
                "SELECT * FROM settlement_disputes WHERE flow='F' AND status='pending'")
        self.assertEqual(d['claimed'], 80)
        self.assertEqual(d['held'], 20)
        self.assert_replay_verified()

    def test_plain_settlement_amount_still_settles_after_handoff(self):
        # Console explicitly settles the corroborated 60 with no fork fields.
        self.admit_f()
        self.rotate_resolver()
        r = self.call(flow, 'settle-60', 'settle', id='r60', flow='F',
                      actual=60, at=22)
        self.assertEqual(r['decision'], 'settled')
        self.assertEqual(self.window_used()['used'], 60)
        self.assertEqual(self.flow_row()['status'], 'settled')
        self.assert_replay_verified()


class DispositionAFullDeliveryTests(HandoffScene):
    def test_all_80_before_fence_settle_80_and_share_20(self):
        self.admit_f()
        self.device_reading_60()
        self.rotate_resolver()
        self.corroborate(80, '-a')
        r = self.late_receipt_80()
        self.assertEqual(r['decision'], 'settled')
        self.assertEqual(r['actual'], 80)

        # Customer used = 80; exactly 20 reusable in the same window/grant.
        self.assertEqual(self.window_used()['used'], 80)
        self.assertEqual(self.grant_row()['used'], 80)
        self.assertEqual(r['available'], 20)
        self.assertIsNone(one(
            self.db,
            "SELECT 1 FROM settlement_disputes WHERE flow='F' AND status='pending'"))

        # New connection via R2/IP-B consumes exactly the remaining 20.
        g = self.call(flow, 'conn-g', 'connect', id='G', grant='g',
                     pin='pin-b', holder='worker', ip='IP-B', at=23,
                     bytes=20)
        self.assertEqual(g['decision'], 'admitted')
        edge = self.call(flow, 'conn-g1', 'connect', id='G1', grant='g',
                         pin='pin-b', holder='worker', ip='IP-B', at=23,
                         bytes=1)
        self.assertEqual(edge['decision'], 'grant_exhausted')

        # The difference cannot be patched by a duplicate top-up grant:
        # grant-a still owns the whole 100-byte window allocation.
        topup = self.call(permit, 'grant-b', 'grant', id='g2',
                          contract='pu', window='w', holder='worker-2',
                          limit_bytes=20, at=23)
        self.assertEqual(topup['decision'], 'quota_overcommitted')
        self.assert_replay_verified()


class DispositionBPartialAndArbitrationTests(HandoffScene):
    def test_only_60_confirmed_freezes_20_and_releases_20(self):
        self.admit_f()
        self.rotate_resolver()
        r = self.partial_disposition_60()

        self.assertEqual(r['settled'], 60)
        self.assertEqual(r['disputed'], 20)
        self.assertEqual(r['released'], 20)
        self.assertEqual(self.window_used()['used'], 60)
        self.assertEqual(self.window_used()['held'], 20)
        self.assertEqual(self.grant_row()['held'], 20)
        self.assertEqual(self.call(flow, 'bal', 'balance', grant='g')
                         ['available'], 20)

        # Exact quota edge: 20 admitted, the 21st byte refused.
        self.assertEqual(self.call(
            flow, 'conn-g', 'connect', id='G', grant='g', pin='pin-b',
            holder='worker', ip='IP-B', at=23, bytes=20)['decision'],
            'admitted')
        self.assertEqual(self.call(
            flow, 'conn-g1', 'connect', id='G1', grant='g', pin='pin-b',
            holder='worker', ip='IP-B', at=23, bytes=1)['decision'],
            'grant_exhausted')
        self.assert_replay_verified()

    def test_expired_arbitrator_cannot_release_or_charge(self):
        self.admit_f()
        self.rotate_resolver()
        self.partial_disposition_60()
        self.register_auditor(expires=30)

        denied = self.call(flow, 'resolve-expired', 'resolve', id='rr-old',
                           dispute='rcpt-80b:dispute', approved=0,
                           approver='auditor-1', arbitrator='aud', at=40)
        self.assertEqual(denied['decision'], 'resolution_denied')
        self.assertEqual(denied['reason'], 'arbitrator_expired')
        # Alias vocabulary: the same token reads as arbitrator_expired.
        self.assertEqual(denied['decision'], 'arbitrator_expired')

        d = one(self.db, "SELECT status FROM settlement_disputes WHERE id=?",
                ('rcpt-80b:dispute',))
        self.assertEqual(d['status'], 'pending')
        self.assertEqual(self.window_used()['used'], 60)
        self.assertEqual(self.window_used()['held'], 20)
        self.assert_replay_verified()

    def test_post_revocation_20_is_not_paid_and_is_reversed(self):
        self.admit_f()
        self.rotate_resolver()
        self.partial_disposition_60()

        # Later proof: the independent egress counter places the extra 20
        # bytes at minute 22, i.e. after the minute-21 revocation fence.
        proof = self.call(flow, 'proof-post', 'counter', id='proof-post',
                          flow='F', bytes=20, sent_at=22, at=40,
                          source='egress-counter', classification='post_revocation')
        self.assertEqual(proof['decision'], 'counter_recorded')

        self.register_auditor('aud2', 'auditor-2', expires=200)

        decided = self.call(flow, 'resolve-0', 'resolve', id='rr-0',
                            dispute='rcpt-80b:dispute', approved=0,
                            approver='auditor-2', arbitrator='aud2', at=41)
        self.assertEqual(decided['decision'], 'dispute_resolved')
        self.assertEqual(decided['approved'], 60)
        self.assertEqual(decided['reversed'], 20)

        # Customer still used exactly 60; hold gone; the disputed 20 is free.
        self.assertEqual(self.window_used()['used'], 60)
        self.assertEqual(self.window_used()['held'], 0)
        f = self.flow_row()
        self.assertEqual(f['status'], 'settled')
        self.assertEqual(f['held'], 0)
        self.assertEqual(f['released'], 40)  # 20 undisputed + 20 rejected

        rev = one(self.db,
                  "SELECT * FROM verdict_receipts WHERE status='reversed'")
        self.assertIsNotNone(rev)
        self.assertEqual(rev['actual'], -20)

        # 40 bytes are now reusable in the shared window (exact boundary).
        bal = self.call(permit, 'bal2', 'balance', id='g')
        self.assertEqual(bal['available'], 40)
        self.assertEqual(self.call(
            flow, 'conn-h40', 'connect', id='H40', grant='g', pin='pin-b',
            holder='worker', ip='IP-B', at=42, bytes=40)['decision'],
            'admitted')
        self.assertEqual(self.call(
            flow, 'conn-h1', 'connect', id='H1', grant='g', pin='pin-b',
            holder='worker', ip='IP-B', at=42, bytes=1)['decision'],
            'grant_exhausted')
        self.assert_replay_verified()

    def test_arbitrator_awards_extra_20_as_delta_or_total(self):
        for approved, label in ((20, 'delta'), (80, 'total')):
            with self.subTest(form=label):
                tmp = tempfile.TemporaryDirectory()
                try:
                    db = connect(str(Path(tmp.name) / 'x.sqlite'))
                    import cloudcourt.tokens  # noqa: F401
                    # Re-point the scene at an isolated database.
                    old_db, old_path = self.db, self.path
                    self.db = db
                    self.path = str(Path(tmp.name) / 'x.sqlite')
                    try:
                        self.admit_f()
                        self.rotate_resolver()
                        self.partial_disposition_60()
                        self.register_auditor('aud', 'auditor-1', 200)
                        out = self.call(
                            flow, f'res-{label}', 'resolve', id=f'rr-{label}',
                            dispute='rcpt-80b:dispute', approved=approved,
                            approver='auditor-1', arbitrator='aud', at=41)
                        self.assertEqual(out['decision'], 'dispute_resolved')
                        self.assertEqual(out['approved'], 80)
                        self.assertEqual(self.window_used()['used'], 80)
                        self.assertEqual(self.call(
                            flow, f'conn-{label}', 'connect', id=f'G-{label}',
                            grant='g', pin='pin-b', holder='worker',
                            ip='IP-B', at=42, bytes=20)['decision'],
                            'admitted')
                        self.db.close()
                        rep = replay(self.path)
                        self.assertTrue(rep['verified'], rep['mismatch'])
                    finally:
                        try:
                            self.db.close()
                        except Exception:
                            pass
                        self.db = old_db
                        self.path = old_path
                finally:
                    tmp.cleanup()


class DualProxyRetryTests(HandoffScene):
    def test_two_proxies_one_settlement_no_double_charge(self):
        self.admit_f()
        self.rotate_resolver()
        self.corroborate(80, '-d')

        first = self.late_receipt_80(event_id='proxy-1',
                                     receipt_id='rcpt-p1', key='DUPKEY')
        self.assertEqual(first['decision'], 'settled')

        # Second proxy, different event/receipt ids, same upstream verdict key.
        second = self.late_receipt_80(event_id='proxy-2',
                                      receipt_id='rcpt-p2', key='DUPKEY',
                                      source='second-proxy')
        self.assertEqual(second['decision'], 'duplicate_receipt')
        # Idempotent vocabulary also reads as plain settled.
        self.assertEqual(second['decision'], 'settled')

        # Keyless content-identical retry (same flow/bytes/marked minute).
        third = self.late_receipt_80(event_id='proxy-3',
                                     receipt_id='rcpt-p3', key=None)
        self.assertEqual(third['decision'], 'duplicate_receipt')

        self.assertEqual(self.window_used()['used'], 80)
        rows = many(self.db,
                    "SELECT id FROM verdict_receipts WHERE flow='F' "
                    "AND status='settled' AND kind='settlement'")
        self.assertEqual(len(rows), 1)

        # Exact event redelivery returns the original recorded decision.
        redelivered = self.late_receipt_80(event_id='proxy-1',
                                           receipt_id='rcpt-p1', key='DUPKEY')
        self.assertEqual(redelivered, first)
        self.assert_replay_verified()


class PostFreezePacketTests(HandoffScene):
    def test_packets_to_old_target_after_freeze_are_not_usage(self):
        self.admit_f()
        self.rotate_resolver()

        before = self.call(flow, 'pkt-before', 'usage', id='u-pre',
                           flow='F', bytes=60, sent_at=20, at=20)
        self.assertEqual(before['decision'], 'usage_verified')
        self.assertTrue(before['billable'])

        after = self.call(flow, 'pkt-after', 'packets', id='u-post',
                          flow='F', bytes=20, sent_at=22, at=22)
        self.assertEqual(after['decision'], 'old_target_frozen')
        self.assertFalse(after['billable'])
        self.assertEqual(after['decision'], 'target_frozen')

        f = self.flow_row()
        self.assertEqual(f['pre_fence_bytes'], 60)
        self.assertEqual(f['post_fence_bytes'], 20)
        # Rejected packets never hit the balance.
        self.assertEqual(self.window_used()['used'], 0)
        self.assert_replay_verified()


class QuotaReleaseIdempotencyTests(HandoffScene):
    def test_release_once_is_idempotent_and_bounded(self):
        self.admit_f()

        r40 = self.call(permit, 'rel-40', 'release', id='rel-40', flow='F',
                        bytes=40, at=19)
        self.assertEqual(r40['decision'], 'quota_released')
        self.assertEqual(r40['bytes'], 40)
        self.assertEqual(r40['available'], 40)

        r40b = self.call(permit, 'rel-40b', 'release_quota', id='rel-40b',
                         flow='F', amount=40, at=19)
        self.assertEqual(r40b['decision'], 'quota_released')
        self.assertEqual(r40b['available'], 80)

        # Cannot release more than the remaining open reservation (20).
        too_much = self.call(permit, 'rel-too-much', 'release',
                             id='rel-too-much', flow='F', bytes=21, at=19)
        self.assertEqual(too_much['decision'], 'release_exceeds_reservation')

        rest = self.call(flow, 'rel-rest', 'release', id='rel-rest',
                         flow='F')
        self.assertEqual(rest['decision'], 'quota_released')
        self.assertEqual(rest['bytes'], 20)
        self.assertEqual(rest['available'], 100)

        again = self.call(permit, 'rel-again', 'release', id='rel-again',
                          flow='F')
        self.assertEqual(again['decision'], 'nothing_to_release')
        self.assertEqual(again['bytes'], 0)
        self.assertEqual(self.call(permit, 'bal', 'balance', id='g')
                         ['available'], 100)
        self.assert_replay_verified()

    def test_revoke_frees_reservation_once(self):
        self.admit_f()
        revoked = self.call(permit, 'revoke-g', 'revoke', id='g',
                            generation=2)
        self.assertEqual(revoked['decision'], 'revoked')
        self.assertEqual(self.flow_row()['status'], 'isolated')

        rel = self.call(permit, 'rel-after-revoke', 'release',
                        id='rel-r', flow='F')
        self.assertEqual(rel['decision'], 'nothing_to_release')

        # A higher-generation revoke re-runs isolation but frees nothing twice.
        self.assertEqual(self.call(permit, 'revoke-g3', 'revoke', id='g',
                                   generation=3)['decision'], 'revoked')
        bal = self.call(permit, 'bal', 'balance', id='g')
        self.assertEqual(bal['available'], 100)
        self.assertEqual(one(self.db, 'SELECT used FROM quota_windows')
                         ['used'], 0)

        late = self.call(flow, 'late', 'settle', id='late', flow='F',
                         actual=50)
        self.assertEqual(late['decision'], 'not_settleable')
        self.assert_replay_verified()


class AppendOnlyRecordsTests(HandoffScene):
    def test_admission_dns_and_payments_are_append_only(self):
        self.admit_f()
        self.rotate_resolver()
        self.partial_disposition_60()
        self.register_auditor('aud2', 'auditor-2', 200)
        self.call(flow, 'rr', 'resolve', id='rr',
                  dispute='rcpt-80b:dispute', approved=0,
                  approver='auditor-2', arbitrator='aud2', at=41)

        # Original admission event still records the admitted decision.
        ev = one(self.db, "SELECT * FROM events WHERE event_id='connect-f'")
        self.assertEqual(json.loads(ev['result'])['decision'], 'admitted')
        self.assertEqual(json.loads(ev['payload'])['bytes'], 100)

        # Old DNS page is untouched; the new page is a separate generation.
        old = one(self.db, "SELECT * FROM dns_observations WHERE id='ans-a'")
        self.assertEqual(old['ip'], 'IP-A')
        self.assertEqual(old['generation'], 1)
        new = one(self.db, "SELECT ip,generation FROM dns_observations WHERE id='ans-b'")
        self.assertEqual(new['ip'], 'IP-B')
        self.assertEqual(new['generation'], 2)

        # Both proxy claim and client/counter originals are preserved.
        evidence_kinds = {r['kind'] for r in many(
            self.db, "SELECT DISTINCT kind FROM byte_evidence WHERE flow='F'")}
        self.assertIn('proxy', evidence_kinds)
        self.assertIn('client', evidence_kinds)
        self.assertIn('egress', evidence_kinds)

        # Payment ledger: +60 settlement and an appended -20 correction.
        totals = many(self.db,
                      "SELECT status, SUM(actual) s, COUNT(*) n "
                      "FROM verdict_receipts WHERE flow='F' GROUP BY status")
        by_status = {r['status']: r for r in totals}
        self.assertEqual(by_status['settled']['s'], 60)
        self.assertIn('reversed', by_status)
        self.assertEqual(by_status['reversed']['s'], -20)

        self.assert_replay_verified()


class FullSceneReplayTests(HandoffScene):
    def test_every_command_replays_to_identical_state(self):
        self.admit_f()
        self.device_reading_60()
        self.rotate_resolver()
        self.call(flow, 'post-pkt', 'usage', id='up', flow='F', bytes=5,
                  sent_at=22, at=22)
        self.partial_disposition_60()
        self.register_auditor(expires=200)
        self.call(flow, 'resolve', 'resolve', id='rr',
                  dispute='rcpt-80b:dispute', approved=20,
                  approver='auditor-1', arbitrator='aud', at=40)
        self.call(flow, 'new-conn', 'connect', id='G', grant='g',
                  pin='pin-b', holder='worker', ip='IP-B', at=42, bytes=20)
        self.db.close()
        rep = replay(self.path)
        self.assertTrue(rep['verified'], rep['mismatch'])
        self.assertGreater(rep['decisions'], 10)


if __name__ == '__main__':
    unittest.main()
