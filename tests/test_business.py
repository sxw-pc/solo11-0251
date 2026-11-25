import json,tempfile,unittest
from pathlib import Path
from cloudcourt import name,permit,flow
from cloudcourt.store import connect,replay,one

def fixture(db,filename,module):
    return [module.run(db,x) for x in json.loads((Path('fixtures')/filename).read_text(encoding='utf-8'))]

class Business(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.path=str(Path(self.tmp.name)/'db.sqlite');self.db=connect(self.path)
    def tearDown(self):self.db.close();self.tmp.cleanup()
    def base(self):
        fixture(self.db,'name-normal.json',name);fixture(self.db,'permit-normal.json',permit)
        flow.run(self.db,{'event_id':'pin','op':'pin','id':'pin-a','observation':'answer-a','at':20})

    def test_resolver_identity_and_late_answer(self):
        self.base()
        self.assertEqual(name.run(self.db,{'event_id':'unknown','op':'observe','id':'bad','profile':'profile-a','resolver':'resolver-a','source':'unknown','ip':'192.0.2.11','generation':2,'observed':20,'expires':30})['decision'],'untrusted_resolver')
        self.assertEqual(name.run(self.db,{'event_id':'old','op':'observe','id':'old','profile':'profile-a','resolver':'resolver-a','source':'resolver-1','ip':'192.0.2.11','generation':1,'observed':20,'expires':30})['decision'],'stale_dns_answer')
        self.assertTrue(replay(self.path)['verified'])

    def test_new_profile_generation_invalidates_old_pin(self):
        self.base()
        name.run(self.db,{'event_id':'new-profile','op':'profile','id':'profile-a','tenant':'tenant-a','host':'api.example.invalid','generation':2})
        self.assertEqual(flow.run(self.db,{'event_id':'connect','op':'connect','id':'flow-a','grant':'grant-a','pin':'pin-a','holder':'worker-a','ip':'192.0.2.10','at':22,'bytes':30})['decision'],'dns_identity_changed')
        self.assertEqual(flow.run(self.db,{'event_id':'new-pin','op':'pin','id':'pin-new','observation':'answer-a','at':22})['decision'],'dns_unavailable')

    def test_resolver_replacement_and_revocation_fence_old_dns(self):
        self.base()
        self.assertEqual(name.run(self.db,{'event_id':'resolver-new','op':'resolver','id':'resolver-a','tenant':'tenant-a','source':'resolver-1','generation':2})['decision'],'resolver_active')
        self.assertEqual(flow.run(self.db,{'event_id':'old-connect','op':'connect','id':'flow-old','grant':'grant-a','pin':'pin-a','holder':'worker-a','ip':'192.0.2.10','at':22,'bytes':20})['decision'],'dns_identity_changed')
        self.assertEqual(permit.run(self.db,{'event_id':'new-grant','op':'grant','id':'grant-b','contract':'purpose-a','window':'window-a','holder':'worker-b','limit_bytes':10,'at':22})['decision'],'destination_unresolved')
        self.assertEqual(name.run(self.db,{'event_id':'new-answer','op':'observe','id':'answer-new','profile':'profile-a','resolver':'resolver-a','source':'resolver-1','ip':'192.0.2.11','generation':2,'observed':22,'expires':100})['decision'],'answer_accepted')
        self.assertEqual(flow.run(self.db,{'event_id':'new-pin','op':'pin','id':'pin-new','observation':'answer-new','at':23})['decision'],'pinned')
        self.assertEqual(name.run(self.db,{'event_id':'resolver-revoke','op':'resolver','id':'resolver-a','tenant':'tenant-a','source':'resolver-1','generation':3,'state':'revoked'})['decision'],'resolver_revoked')
        self.assertEqual(flow.run(self.db,{'event_id':'revoked-connect','op':'connect','id':'flow-revoked','grant':'grant-a','pin':'pin-new','holder':'worker-a','ip':'192.0.2.11','at':24,'bytes':20})['decision'],'dns_identity_changed')
        self.assertTrue(replay(self.path)['verified'])

    def test_quota_and_settlement_change_next_connection(self):
        self.base()
        self.assertEqual(permit.run(self.db,{'event_id':'over-grant','op':'grant','id':'g2','contract':'purpose-a','window':'window-a','holder':'worker-b','limit_bytes':700,'at':20})['decision'],'quota_overcommitted')
        self.assertEqual(flow.run(self.db,{'event_id':'conn','op':'connect','id':'flow-a','grant':'grant-a','pin':'pin-a','holder':'worker-a','ip':'192.0.2.10','at':21,'bytes':300})['decision'],'admitted')
        self.assertEqual(flow.run(self.db,{'event_id':'dispute','op':'settle','id':'bad','flow':'flow-a','actual':301})['decision'],'usage_dispute')
        self.assertEqual(flow.run(self.db,{'event_id':'settle','op':'settle','id':'receipt-a','flow':'flow-a','actual':280})['decision'],'pending_dispute')
        permit.run(self.db,{'event_id':'auditor','op':'arbitrator','id':'auditor-a','tenant':'tenant-a','actor':'auditor-a','role':'auditor','generation':1,'at':20,'expires':50})
        self.assertEqual(flow.run(self.db,{'event_id':'forged','op':'resolve','id':'forged','dispute':'bad','approved':280,'approver':'stranger','arbitrator':'auditor-a','at':23})['decision'],'resolution_denied')
        self.assertEqual(flow.run(self.db,{'event_id':'resolve','op':'resolve','id':'receipt-resolved','dispute':'bad','approved':280,'approver':'auditor-a','arbitrator':'auditor-a','at':23})['decision'],'dispute_resolved')
        self.assertEqual(flow.run(self.db,{'event_id':'too-many','op':'connect','id':'flow-b','grant':'grant-a','pin':'pin-a','holder':'worker-a','ip':'192.0.2.10','at':22,'bytes':200})['decision'],'grant_exhausted')
        self.assertEqual(one(self.db,'SELECT used FROM quota_windows WHERE id=?',('window-a',))['used'],280)
        self.assertTrue(replay(self.path)['verified'])

    def test_revocation_and_transfer_isolate_inflight(self):
        self.base()
        flow.run(self.db,{'event_id':'conn','op':'connect','id':'flow-a','grant':'grant-a','pin':'pin-a','holder':'worker-a','ip':'192.0.2.10','at':21,'bytes':100})
        self.assertEqual(permit.run(self.db,{'event_id':'wrong-transfer','op':'transfer','id':'grant-a','from_holder':'wrong','to_holder':'worker-b','generation':2})['decision'],'transfer_denied')
        self.assertEqual(permit.run(self.db,{'event_id':'revoke','op':'revoke','id':'grant-a','generation':2})['decision'],'revoked')
        self.assertEqual(one(self.db,'SELECT status FROM flow_attempts WHERE id=?',('flow-a',))['status'],'isolated')
        self.assertEqual(flow.run(self.db,{'event_id':'late-settle','op':'settle','id':'receipt','flow':'flow-a','actual':50})['decision'],'not_settleable')

    def test_isolated_dns_answer_blocks_existing_pin(self):
        self.base()
        self.assertEqual(name.run(self.db,{'event_id':'isolate','op':'isolate','id':'answer-a'})['decision'],'answer_isolated')
        self.assertEqual(flow.run(self.db,{'event_id':'conn','op':'connect','id':'flow-a','grant':'grant-a','pin':'pin-a','holder':'worker-a','ip':'192.0.2.10','at':21,'bytes':100})['decision'],'connection_denied')

    def test_flagged_connection_quarantines_destination_and_grants(self):
        self.base()
        flow.run(self.db,{'event_id':'conn','op':'connect','id':'flow-a','grant':'grant-a','pin':'pin-a','holder':'worker-a','ip':'192.0.2.10','at':21,'bytes':100})
        self.assertEqual(flow.run(self.db,{'event_id':'flag','op':'flag','id':'flag-a','flow':'flow-a'})['decision'],'flagged')
        self.assertEqual(name.run(self.db,{'event_id':'review','op':'review','profile':'profile-a'})['decision'],'destination_quarantined')
        self.assertEqual(one(self.db,'SELECT state FROM egress_grants WHERE id=?',('grant-a',))['state'],'revoked')
        self.assertEqual(flow.run(self.db,{'event_id':'retry','op':'connect','id':'flow-b','grant':'grant-a','pin':'pin-a','holder':'worker-a','ip':'192.0.2.10','at':22,'bytes':10})['decision'],'connection_denied')
        self.assertTrue(replay(self.path)['verified'])

    def test_business_id_collision_does_not_replace_purpose(self):
        self.base()
        result=permit.run(self.db,{'event_id':'new-purpose-event','op':'purpose','id':'purpose-a','tenant':'tenant-a','profile':'profile-a','purpose':'different'})
        self.assertEqual(result['decision'],'business_identity_conflict')
        self.assertEqual(one(self.db,'SELECT purpose FROM purpose_contracts WHERE id=?',('purpose-a',))['purpose'],'fetch-api')
