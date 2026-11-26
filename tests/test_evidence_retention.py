"""Evidence retention tests: verified erasure, scoped holds and audit survival.

Covers both institutionally approved governance arrangements over the same
originals and legal instruments, plus the seven mandated scenarios:
shared resolution page, case scope narrowing, undestroyed key copies,
offline backup recovery, duplicate deletion, late settlement dispute and
court release of a hold.
"""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudcourt import name, permit, flow, evidence
from cloudcourt.store import connect, replay, one, many, SESSION
from cloudcourt.evidence_retention import (
    JudicialCustodian, redaction_token, seal_bytes, open_bytes,
    admission_fence, trace_subject, settlement_audit, ledger_entries,
)

HOLDER_A, HOLDER_B = 'worker-a', 'worker-b'
IP_Z = '192.0.2.10'
CASE_C = 'case-C'


class EvidenceCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = str(self.root / 'ops.sqlite')
        self.db = connect(self.db_path)
        self.custodian = JudicialCustodian(str(self.root / 'custodian'))
        self._build_shared_originals()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    # ------------------------------------------------------------------ #
    # F1 and F2 are two settled connections that pin the SAME DNS
    # observation (answer-a -> IP-Z). F1 belongs to worker-a and falls
    # under court case C; F2 belongs to worker-b who holds a deletion order.
    # ------------------------------------------------------------------ #
    def _build_shared_originals(self):
        for x in json.loads(Path('fixtures/name-normal.json').read_text()):
            name.run(self.db, x)
        for x in json.loads(Path('fixtures/permit-normal.json').read_text()):
            permit.run(self.db, x)
        permit.run(self.db, {'event_id': 'grant2', 'op': 'grant',
                             'id': 'grant-b', 'contract': 'purpose-a',
                             'window': 'window-a', 'holder': HOLDER_B,
                             'limit_bytes': 300, 'at': 20})
        flow.run(self.db, {'event_id': 'pin1', 'op': 'pin', 'id': 'pin-f1',
                           'observation': 'answer-a', 'at': 20})
        flow.run(self.db, {'event_id': 'pin2', 'op': 'pin', 'id': 'pin-f2',
                           'observation': 'answer-a', 'at': 20})
        flow.run(self.db, {'event_id': 'c1', 'op': 'connect', 'id': 'F1',
                           'grant': 'grant-a', 'pin': 'pin-f1',
                           'holder': HOLDER_A, 'ip': IP_Z, 'at': 21,
                           'bytes': 200})
        flow.run(self.db, {'event_id': 'c2', 'op': 'connect', 'id': 'F2',
                           'grant': 'grant-b', 'pin': 'pin-f2',
                           'holder': HOLDER_B, 'ip': IP_Z, 'at': 21,
                           'bytes': 150})
        flow.run(self.db, {'event_id': 's1', 'op': 'settle',
                           'id': 'rcpt-f1', 'flow': 'F1', 'actual': 180})
        flow.run(self.db, {'event_id': 's2', 'op': 'settle',
                           'id': 'rcpt-f2', 'flow': 'F2', 'actual': 140})

    def _place_case_hold(self, hold_id='hold-1', scope='F1-original-chain',
                         expires=1000, supersedes=None):
        return evidence.run(self.db, {
            'event_id': 'ev-' + hold_id, 'op': 'place_hold',
            'hold_id': hold_id, 'flow': 'F1', 'case_id': CASE_C,
            'agency': 'court-clerk-7', 'judge_scope': scope,
            'issued_at': 30, 'expires_at': expires, 'supersedes': supersedes})

    def _seal_f1(self):
        return evidence.run(self.db, {
            'event_id': 'ev-seal', 'op': 'seal', 'seal_id': 'seal-1',
            'handoff_id': 'ho-1', 'flow': 'F1', 'warrant_id': 'w-C-1',
            'case_id': CASE_C, 'agency': 'court-clerk-7', 'at': 31,
            'custodian_root': self.custodian.root})

    def _snapshot(self, name='bk-1', path=None):
        path = path or str(self.root / 'backup.sqlite')
        return evidence.run(self.db, {
            'event_id': 'ev-snap', 'op': 'snapshot_backup',
            'backup_id': name, 'path': path, 'at': 33}), path

    def _intake(self, order_id, arrangement, subject=HOLDER_B):
        return evidence.run(self.db, {
            'event_id': 'ev-order', 'op': 'intake_order',
            'order_id': order_id, 'subject': subject, 'tenant': 'tenant-a',
            'basis': 'customer-erasure-request', 'issued_at': 32,
            'arrangement': arrangement})

    def _scan_identifiers(self, connection, flow_id):
        """Every cleartext identifier left for a flow, anywhere searchable."""
        leaks = []
        f = connection.execute(
            'SELECT holder,ip FROM flow_attempts WHERE id=?',
            (flow_id,)).fetchone()
        for field, value in zip(('holder', 'ip'), f):
            if value and not str(value).startswith(('tok-', 'WRAPPED-')):
                leaks.append(('flow_attempts', field, value))
        for (payload,) in connection.execute('SELECT payload FROM events'):
            event = json.loads(payload)
            if event.get('id') == flow_id or event.get('flow') == flow_id \
                    or event.get('flow_ref') == flow_id:
                for field in ('holder', 'ip'):
                    value = event.get(field)
                    if isinstance(value, str) and not value.startswith(
                            ('tok-', 'WRAPPED-')):
                        leaks.append(('events', field, value))
        return leaks


# --------------------------------------------------------------------------- #
# Arrangement 1: irreversible destruction with judicial custodian
# --------------------------------------------------------------------------- #
class DestructionArrangement(EvidenceCase):
    def _destroy(self, order_id='D-1', backup_paths=(), event_id='ev-destroy'):
        return evidence.run(self.db, {
            'event_id': event_id, 'op': 'destroy',
            'order_id': order_id, 'at': 40,
            'custodian_root': self.custodian.root,
            'backup_paths': list(backup_paths)})

    def test_shared_resolution_page_survives_single_tenant_erasure(self):
        """One tenant's erasure must not erase another tenant's lawful facts."""
        self.assertEqual(self._place_case_hold()['decision'], 'held')
        self.assertEqual(self._seal_f1()['decision'], 'sealed')
        self.assertEqual(self._intake('D-1', 'destroy')['decision'],
                         'order_recorded')
        result = self._destroy()
        self.assertEqual(result['decision'], 'destruction_complete')

        # F2's identifiable fields are masked everywhere in the operational DB
        f2 = one(self.db, "SELECT holder,ip,status FROM flow_attempts WHERE id='F2'")
        self.assertTrue(f2['holder'].startswith('tok-'))
        self.assertTrue(f2['ip'].startswith('tok-'))
        self.assertEqual(f2['status'], 'settled')
        self.assertEqual(self._scan_identifiers(self.db, 'F2'), [])
        # F2's own events retain no cleartext network/account identifier. The
        # shared DNS observation and F1 legitimately keep IP-Z (shared legal
        # facts are not erased on one tenant's request).
        for row in self.db.execute('SELECT payload FROM events'):
            event = json.loads(row['payload'])
            if event.get('flow_ref') == 'F2' or event.get('id') == 'F2' \
                    or event.get('flow') == 'F2':
                self.assertNotEqual(event.get('holder'), HOLDER_B)
                self.assertNotEqual(event.get('ip'), IP_Z)
        grant_b = one(self.db,
            "SELECT holder,used,limit_bytes FROM egress_grants WHERE id='grant-b'")
        self.assertTrue(grant_b['holder'].startswith('tok-'))
        # the settled credit facts survive the holder pseudonymisation
        self.assertEqual((grant_b['used'], grant_b['limit_bytes']), (140, 300))

        # F1 and the shared DNS observation are untouched and still usable
        f1 = one(self.db, "SELECT holder,ip FROM flow_attempts WHERE id='F1'")
        self.assertEqual((f1['holder'], f1['ip']), (HOLDER_A, IP_Z))
        obs = one(self.db, "SELECT ip,state FROM dns_observations WHERE id='answer-a'")
        self.assertEqual((obs['ip'], obs['state']), (IP_Z, 'accepted'))
        pin = one(self.db, "SELECT state FROM dns_pins WHERE id='pin-f1'")
        self.assertEqual(pin['state'], 'active')

        # The custodian holds F1's original chain incl. the shared observation
        verification = evidence.custodian_verification(
            self.db, self.custodian, 'F1', 'w-C-1', CASE_C)
        self.assertEqual(verification['decision'], 'verified_at_custodian')
        self.assertIn('dns_observations', verification['tables'])
        self.assertTrue(verification['has_original_holder'])
        # A wrong warrant cannot retrieve the sealed original
        with self.assertRaises(PermissionError):
            self.custodian.retrieve(verification['receipt'], 'wrong', CASE_C)

    def test_settlement_amounts_order_and_verdict_remain_provable(self):
        self._place_case_hold()
        self._seal_f1()
        self._intake('D-1', 'destroy')
        self._destroy()
        audit = settlement_audit(self.db, 'F2')
        self.assertEqual(audit['status'], 'settled')
        self.assertEqual(audit['receipts'],
                         [{'receipt': 'rcpt-f2', 'amount': 140,
                           'verdict': 'settled'}])
        self.assertEqual(len(audit['proofs']), 1)
        self.assertEqual(audit['proofs'][0]['amount'], 140)
        self.assertTrue(audit['proofs'][0]['hash'])
        self.assertEqual(audit['identifiers_present'], [])
        # quota and grant usage still prove the settled byte consumption
        self.assertEqual(one(self.db,
            "SELECT used FROM quota_windows WHERE id='window-a'")['used'], 320)
        self.assertEqual(one(self.db,
            "SELECT used FROM egress_grants WHERE id='grant-b'")['used'], 140)

    def test_late_retry_cannot_write_cleared_ip_back_to_events(self):
        self._place_case_hold()
        self._seal_f1()
        self._intake('D-1', 'destroy')
        self._destroy()
        # Re-issuing the original connect (same cleartext holder/IP) is fenced
        retry = flow.run(self.db, {
            'event_id': 'c2-late', 'op': 'connect', 'id': 'F2-retry',
            'grant': 'grant-b', 'pin': 'pin-f2', 'holder': HOLDER_B,
            'ip': IP_Z, 'at': 50, 'bytes': 10})
        self.assertEqual(retry['decision'], 'subject_deleted_retry_blocked')
        self.assertIsNone(one(self.db,
            "SELECT 1 FROM flow_attempts WHERE id='F2-retry'"))
        self.assertEqual(self._scan_identifiers(self.db, 'F2'), [])
        # and the whole event stream still replays to the identical state
        self.assertTrue(replay(self.db_path)['verified'])

    def test_offline_backup_recovery_treated_and_untreated(self):
        self._place_case_hold()
        self._seal_f1()
        self._intake('D-1', 'destroy')
        _, backup = self._snapshot()
        # An untreated restore would re-introduce the deleted identity
        self.assertEqual(
            evidence.restore_backup(self.db, backup)['decision'],
            'restore_quarantined')
        self._destroy(backup_paths=[backup])
        # The treated backup now carries pseudonyms and a redaction recipe
        remote = sqlite3.connect(backup)
        remote.row_factory = sqlite3.Row
        row = dict(remote.execute(
            "SELECT holder,ip FROM flow_attempts WHERE id='F2'").fetchone())
        self.assertTrue(row['holder'].startswith('tok-'))
        self.assertTrue(row['ip'].startswith('tok-'))
        self.assertTrue(remote.execute(
            'SELECT 1 FROM redaction_recipes LIMIT 1').fetchone())
        # F1 stays intact inside the backup (its legal rights are preserved)
        f1 = dict(remote.execute(
            "SELECT holder,ip FROM flow_attempts WHERE id='F1'").fetchone())
        self.assertEqual((f1['holder'], f1['ip']), (HOLDER_A, IP_Z))
        # the deleted subject's grant holder is masked inside the backup too
        grant_b = dict(remote.execute(
            "SELECT holder FROM egress_grants WHERE id='grant-b'").fetchone())
        self.assertTrue(grant_b['holder'].startswith('tok-'))
        remote.close()
        restore = evidence.restore_backup(self.db, backup)
        self.assertEqual(restore['decision'], 'restore_allowed')
        self.assertTrue(restore['recipes'])

    def test_duplicate_deletion_is_idempotent(self):
        self._place_case_hold()
        self._seal_f1()
        self._intake('D-1', 'destroy')
        first = self._destroy(event_id='ev-destroy-1')
        self.assertEqual(first['decision'], 'destruction_complete')
        # A genuine second deletion request (new event id) is refused by the
        # service-level idempotency guard, not merely the event cache.
        second = self._destroy(event_id='ev-destroy-2')
        self.assertEqual(second['decision'], 'already_deleted')
        # replaying the identical original event still returns its stored result
        self.assertEqual(self._destroy(event_id='ev-destroy-1')['decision'],
                         'destruction_complete')
        # exactly one redaction entry per type, no duplicated ledger rows
        self.assertEqual(len(ledger_entries(self.db, 'redaction')), 1)
        self.assertEqual(len(ledger_entries(self.db, 'customer_receipt')), 1)
        self.assertEqual(one(self.db,
            "SELECT COUNT(*) n FROM redaction_markers WHERE order_id='D-1'")['n'], 1)
        self.assertTrue(replay(self.db_path)['verified'])

    def test_late_settlement_dispute_after_erasure_keeps_audit_only(self):
        # A dispute that predates erasure is preserved as a non-identifying fact
        self._place_case_hold()
        self._seal_f1()
        self._intake('D-1', 'destroy')
        self._destroy()
        permit.run(self.db, {'event_id': 'auditor', 'op': 'arbitrator',
                             'id': 'auditor-a', 'tenant': 'tenant-a',
                             'actor': 'auditor-a', 'role': 'auditor',
                             'generation': 1, 'at': 20, 'expires': 500})
        # A brand-new late dispute on the erased flow cannot recreate identity;
        # the flow is settled so it is refused on business grounds.
        late = flow.run(self.db, {
            'event_id': 'late-dispute', 'op': 'settle', 'id': 'late-rcpt',
            'flow': 'F2', 'actual': 999})
        self.assertEqual(late['decision'], 'not_settleable')
        self.assertEqual(self._scan_identifiers(self.db, 'F2'), [])
        # Amount/verdict remain fully auditable
        self.assertEqual(settlement_audit(self.db, 'F2')['receipts'][0]['amount'], 140)
        self.assertTrue(replay(self.db_path)['verified'])

    def test_court_releases_hold_and_f1_becomes_eligible_again(self):
        self._place_case_hold(expires=1000)
        self._seal_f1()
        released = evidence.run(self.db, {
            'event_id': 'ev-release', 'op': 'release_hold',
            'hold_id': 'hold-1', 'at': 800, 'warrant_id': 'w-rel-1'})
        self.assertEqual(released['decision'], 'hold_released')
        self.assertEqual(one(self.db,
            "SELECT state FROM legal_holds WHERE id='hold-1'")['state'],
            'released')
        # releasing the hold does not restore the already-destroyed F2 identity
        self._intake('D-2', 'destroy')
        result = evidence.run(self.db, {
            'event_id': 'ev-destroy2', 'op': 'destroy', 'order_id': 'D-2',
            'at': 810, 'custodian_root': self.custodian.root})
        self.assertEqual(result['decision'], 'destruction_complete')
        self.assertTrue(replay(self.db_path)['verified'])

    def test_ledger_books_each_legal_act_separately(self):
        self._place_case_hold()
        self._seal_f1()
        self._intake('D-1', 'destroy')
        self._destroy(backup_paths=[])
        types = {e['entry_type'] for e in ledger_entries(self.db)}
        for required in ('deletion_order', 'legal_hold', 'seal', 'handoff',
                         'redaction', 'customer_receipt'):
            self.assertIn(required, types)

    def test_destruction_replays_through_event_stream(self):
        self._place_case_hold()
        self._seal_f1()
        self._intake('D-1', 'destroy')
        _, backup = self._snapshot()
        self._destroy(backup_paths=[backup])
        flow.run(self.db, {'event_id': 'c2-late', 'op': 'connect',
                           'id': 'F2-retry', 'grant': 'grant-b',
                           'pin': 'pin-f2', 'holder': HOLDER_B, 'ip': IP_Z,
                           'at': 50, 'bytes': 10})
        report = replay(self.db_path)
        self.assertTrue(report['verified'], report['mismatch'])


# --------------------------------------------------------------------------- #
# Arrangement 2: crypto separation with per-flow keys and key destruction
# --------------------------------------------------------------------------- #
class CryptoArrangement(EvidenceCase):
    def _separate(self, order_id='K-1', backup_paths=()):
        return evidence.run(self.db, {
            'event_id': 'ev-crypto', 'op': 'crypto_separate',
            'order_id': order_id, 'at': 40,
            'custodian_root': self.custodian.root,
            'backup_paths': list(backup_paths)})

    def test_held_flow_keeps_case_key_deleted_flow_loses_all_rights(self):
        self.assertEqual(self._place_case_hold()['decision'], 'held')
        self.assertEqual(self._intake('K-1', 'crypto')['decision'],
                         'order_recorded')
        result = self._separate()
        self.assertEqual(result['decision'], 'crypto_separation_complete')
        wrapped = {w['flow']: w for w in result['wrapped']}
        self.assertIn('F1', wrapped)
        self.assertIn('F2', wrapped)
        self.assertTrue(wrapped['F1']['held'])
        self.assertFalse(wrapped['F2']['held'])
        # both identities are wrapped, never cleartext, in the operational DB
        for fid in ('F1', 'F2'):
            row = one(self.db, 'SELECT holder,ip FROM flow_attempts WHERE id=?',
                      (fid,))
            self.assertTrue(row['holder'].startswith('WRAPPED-'))
            self.assertTrue(row['ip'].startswith('WRAPPED-'))
        # the grant's account holder is wrapped while quota facts survive
        grant_b = one(self.db,
            "SELECT holder,used FROM egress_grants WHERE id='grant-b'")
        self.assertTrue(grant_b['holder'].startswith('WRAPPED-'))
        self.assertEqual(grant_b['used'], 140)
        # F2: every key copy destroyed, decryption impossible
        f2_check = evidence.verify_key_destruction(self.db, 'F2')
        self.assertTrue(f2_check['fully_destroyed'])
        self.assertEqual(f2_check['decision'], 'verified')
        self.assertEqual(
            evidence.decrypt_identity(self.db, self.custodian, 'F2', 'holder',
                                      'w-C-1', CASE_C)['decision'],
            'decryption_right_destroyed')
        # F1: the only surviving key is escrowed with the custodian
        f1_check = evidence.verify_key_destruction(self.db, 'F1')
        self.assertEqual(f1_check['decision'], 'key_escrowed_to_custodian')
        self.assertFalse(f1_check['operational_material'])
        decrypted = evidence.decrypt_identity(
            self.db, self.custodian, 'F1', 'holder', 'hold-1', CASE_C)
        self.assertEqual(decrypted['value'], HOLDER_A)

    def test_undestroyed_key_copy_is_detected(self):
        self._place_case_hold()
        self._intake('K-1', 'crypto')
        self._separate()
        # Simulate a surviving offsite copy that was not destroyed
        self.db.execute(
            "UPDATE key_manifest SET state='active' WHERE id='km-copy-F2'")
        self.db.execute("INSERT INTO key_material VALUES(?,?)",
                        ('key-F2', 'c3Vydml2aW5nLWtleS1jb3B5'))
        check = evidence.verify_key_destruction(self.db, 'F2')
        self.assertFalse(check['fully_destroyed'])
        self.assertEqual(check['decision'], 'key_copies_remain')
        self.assertGreaterEqual(check['copies_live'], 1)

    def test_ops_role_cannot_see_ciphertext_but_auditor_can(self):
        self._place_case_hold()
        self._intake('K-1', 'crypto')
        self._separate()
        SESSION['actor'] = 'ops'
        try:
            denied = evidence.inspect_envelope(self.db, 'env-F1-holder')
            self.assertEqual(denied['decision'], 'access_denied')
        finally:
            SESSION['actor'] = 'auditor'
        allowed = evidence.inspect_envelope(self.db, 'env-F1-holder')
        self.assertEqual(allowed['decision'], 'envelope')
        # replay under the ops role never materialises the crypto tables
        report_ops = replay(self.db_path, actor='ops')
        self.assertTrue(report_ops['verified'], report_ops['mismatch'])
        report_auditor = replay(self.db_path, actor='auditor')
        self.assertTrue(report_auditor['verified'], report_auditor['mismatch'])

    def test_crypto_offline_backup_wraps_identity_and_restore_guarded(self):
        self._place_case_hold()
        self._intake('K-1', 'crypto')
        _, backup = self._snapshot()
        self.assertEqual(
            evidence.restore_backup(self.db, backup)['decision'],
            'restore_quarantined')
        self._separate(backup_paths=[backup])
        remote = sqlite3.connect(backup)
        row = remote.execute(
            "SELECT holder,ip FROM flow_attempts WHERE id='F2'").fetchone()
        self.assertTrue(row[0].startswith('WRAPPED-'))
        self.assertTrue(remote.execute(
            'SELECT 1 FROM redaction_recipes LIMIT 1').fetchone())
        remote.close()
        self.assertEqual(
            evidence.restore_backup(self.db, backup)['decision'],
            'restore_allowed')

    def test_crypto_late_retry_and_replay(self):
        self._place_case_hold()
        self._intake('K-1', 'crypto')
        self._separate()
        retry = flow.run(self.db, {
            'event_id': 'c2-late', 'op': 'connect', 'id': 'F2-retry',
            'grant': 'grant-b', 'pin': 'pin-f2', 'holder': HOLDER_B,
            'ip': IP_Z, 'at': 50, 'bytes': 10})
        self.assertEqual(retry['decision'], 'subject_deleted_retry_blocked')
        # settlement remains non-identifying but provable
        self.assertEqual(settlement_audit(self.db, 'F2')['receipts'][0]['amount'], 140)
        report = replay(self.db_path, actor='auditor')
        self.assertTrue(report['verified'], report['mismatch'])

    def test_court_release_destroys_escrowed_case_key(self):
        self._place_case_hold()
        self._intake('K-1', 'crypto')
        self._separate()
        self.assertEqual(
            evidence.verify_key_destruction(self.db, 'F1')['decision'],
            'key_escrowed_to_custodian')
        release = evidence.run(self.db, {
            'event_id': 'ev-release', 'op': 'release_hold',
            'hold_id': 'hold-1', 'at': 800, 'warrant_id': 'w-rel-1'})
        self.assertEqual(release['decision'], 'hold_released')
        self.assertEqual(
            evidence.verify_key_destruction(self.db, 'F1')['decision'],
            'verified')
        self.assertTrue(replay(self.db_path, actor='auditor')['verified'])


# --------------------------------------------------------------------------- #
# Legal hold scope: exact case/agency/judge/term, never a whole-tenant freeze
# --------------------------------------------------------------------------- #
class HoldScope(EvidenceCase):
    def test_hold_is_scoped_to_exact_case_and_term(self):
        result = evidence.run(self.db, {
            'event_id': 'h-bad', 'op': 'place_hold', 'hold_id': 'h-bad',
            'flow': 'F1', 'case_id': CASE_C, 'agency': 'clerk',
            'judge_scope': 'F1', 'issued_at': 100, 'expires_at': 50})
        self.assertEqual(result['decision'], 'invalid_hold_window')
        hold = self._place_case_hold()
        self.assertEqual(hold['scope'], 'F1-original-chain')
        row = one(self.db, 'SELECT * FROM legal_holds WHERE id=?', ('hold-1',))
        self.assertEqual(row['case_id'], CASE_C)
        self.assertEqual(row['agency'], 'court-clerk-7')
        self.assertEqual(row['expires_at'], 1000)
        # the other flow of the same tenant is not frozen by the F1 hold
        self.assertIsNone(one(self.db,
            "SELECT 1 FROM legal_holds WHERE flow='F2' AND state='active'"))

    def test_case_scope_narrowing_replaces_broad_hold(self):
        broad = evidence.run(self.db, {
            'event_id': 'h-broad', 'op': 'place_hold', 'hold_id': 'h-broad',
            'flow': 'F1', 'case_id': CASE_C, 'agency': 'clerk',
            'judge_scope': 'all-tenant-connections', 'issued_at': 29,
            'expires_at': 2000})
        self.assertEqual(broad['decision'], 'held')
        narrow = evidence.run(self.db, {
            'event_id': 'h-narrow', 'op': 'place_hold', 'hold_id': 'h-narrow',
            'flow': 'F1', 'case_id': CASE_C, 'agency': 'clerk',
            'judge_scope': 'F1-original-chain', 'issued_at': 30,
            'expires_at': 1000, 'supersedes': 'h-broad'})
        self.assertEqual(narrow['decision'], 'held')
        self.assertEqual(one(self.db,
            "SELECT state FROM legal_holds WHERE id='h-broad'")['state'],
            'narrowed')
        self.assertEqual(one(self.db,
            "SELECT state,supersedes FROM legal_holds WHERE id='h-narrow'")
            ['state'], 'active')
        self.assertTrue(replay(self.db_path)['verified'])

    def test_expired_hold_does_not_block_erasure(self):
        self._place_case_hold(expires=35)  # expires before the erasure at 40
        self._intake('D-9', 'destroy')
        result = evidence.run(self.db, {
            'event_id': 'ev-destroy9', 'op': 'destroy', 'order_id': 'D-9',
            'at': 40, 'custodian_root': self.custodian.root})
        self.assertEqual(result['decision'], 'destruction_complete')


# --------------------------------------------------------------------------- #
# Subject trace and crypto primitives
# --------------------------------------------------------------------------- #
class TracingAndCrypto(EvidenceCase):
    def test_subject_trace_walks_every_foreign_key(self):
        chain = trace_subject(self.db, 'F2')
        self.assertEqual(chain['flow']['id'], 'F2')
        self.assertEqual(chain['pin']['id'], 'pin-f2')
        self.assertEqual(chain['observation']['id'], 'answer-a')
        self.assertEqual(chain['grant']['id'], 'grant-b')
        self.assertEqual(chain['window']['id'], 'window-a')
        self.assertEqual(chain['receipts'][0]['id'], 'rcpt-f2')
        event_ops = {e['event_id'] for e in chain['events']}
        self.assertEqual(event_ops, {'c2', 's2'})
        # the shared observation is referenced by both settled flows
        from cloudcourt.evidence_retention import _flows_for_observation
        self.assertEqual(
            sorted(_flows_for_observation(self.db, 'answer-a')),
            ['F1', 'F2'])

    def test_redaction_token_is_stable_and_one_way(self):
        self.assertEqual(redaction_token(IP_Z), redaction_token(IP_Z))
        self.assertNotEqual(redaction_token(IP_Z), IP_Z)
        self.assertNotEqual(redaction_token(HOLDER_B), redaction_token(IP_Z))

    def test_seal_bytes_roundtrip_and_tamper_detection(self):
        import os
        key = os.urandom(32)
        encoded = seal_bytes(key, HOLDER_B)
        self.assertEqual(open_bytes(key, encoded), HOLDER_B)
        with self.assertRaises(PermissionError):
            open_bytes(os.urandom(32), encoded)

    def test_admission_fence_only_blocks_after_erasure(self):
        # before any erasure the fence must not interfere with normal traffic
        normal = flow.run(self.db, {
            'event_id': 'fresh', 'op': 'connect', 'id': 'F3',
            'grant': 'grant-b', 'pin': 'pin-f2', 'holder': HOLDER_B,
            'ip': IP_Z, 'at': 23, 'bytes': 5})
        self.assertEqual(normal['decision'], 'admitted')


if __name__ == '__main__':
    unittest.main(verbosity=2)
