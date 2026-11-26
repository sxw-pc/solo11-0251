"""research_release 验收测试。

覆盖任务点名的八类情形：
1. 异字节同根因          2. 同症状不同根因      3. 供应商旧故障单
4. 补丁 Q 正常答案回归    5. 可逆真实租户查询     6. 私下披露/盐复用证据
7. 付款退票              8. 公告送达后更正
另覆盖：临时报酬 30 接入、雇佣/许可/保管、两条交易路径差异、P 回退重算、
event_id 幂等，以及裸 sqlite3 连接兼容性。
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cloudcourt.store import connect
from cloudcourt.dns_research import submit
from cloudcourt.research_award import provisional_award
from cloudcourt.poison_probe import evaluate as probe_evaluate
from cloudcourt import research_release as rr


class ReleaseCase(unittest.TestCase):
    def setUp(self):
        self.db = connect(':memory:')
        rr.seed_standard_case(self.db)

    def tearDown(self):
        self.db.close()

    # ---- 1 & 2：根因关联，不靠哈希/摘要/症状机械去重 ---------------------

    def test_different_bytes_can_share_root_cause(self):
        d_r1 = rr.trajectory_bytes(self.db, 'trace-r1')
        d_r1b = rr.trajectory_bytes(self.db, 'trace-r1b')
        self.assertIsNotNone(d_r1)
        self.assertNotEqual(d_r1, d_r1b)  # 两份轨迹字节不同
        self.assertTrue(rr.digests_differ(self.db, 'trace-r1', 'trace-r1b'))
        # 但因果链指向同一个根因（P/Q 差分指纹相同）。
        self.assertTrue(rr.same_root_cause(self.db, 'R1', 'R1B'))
        attr = rr.attribute_causes(self.db)
        self.assertTrue(any(
            x['a'] == 'trace-r1' and x['b'] == 'trace-r1b'
            for x in attr['different_bytes_same_cause']))

    def test_same_symptom_can_have_different_root_causes(self):
        r1 = rr.get_trajectory(self.db, 'trace-r1')
        r2 = rr.get_trajectory(self.db, 'trace-r2')
        self.assertNotEqual(r1['byte_digest'], r2['byte_digest'])
        self.assertEqual(r1['symptom'], r2['symptom'])  # 表面结果相同
        self.assertFalse(rr.same_root_cause(self.db, 'R1', 'R2'))
        # 近因分支不同（P 差分），但同属“缺少可验证绑定”的上层根因族（Q 全阻）。
        self.assertTrue(rr.same_cause_family(self.db, 'R1', 'R2'))
        attr = rr.attribute_causes(self.db)
        pair = next(x for x in attr['same_symptom_different_cause']
                    if {x['a'], x['b']} == {'trace-r1', 'trace-r2'})
        self.assertIn(rr.RC_SOURCE, pair['causes_a'] + pair['causes_b'])
        self.assertIn(rr.RC_REPLAY, pair['causes_a'] + pair['causes_b'])
        self.assertIsNotNone(attr['dedup_by_summary_would_misattribute'])

    def test_equal_report_hash_is_not_independent_discovery(self):
        # 第三方报告与 R1 完全相同的 proof_digest：哈希相同既不能证明独立，
        # 也不会在根因台账里凭空造出第二个根因。
        res = submit(self.db, 'R3', 'someone', 'update.example.invalid',
                     'digest-r1', 1)
        self.assertIn(res['decision'], ('submitted', 'reused'))
        self.assertIsNone(rr.submission_independence(self.db, 'R1', 'R3')
                          .get('research_process_independent'))
        causes = {g['root_cause'] for g in rr.root_cause_groups(self.db)}
        self.assertEqual(causes, {rr.RC_SOURCE, rr.RC_REPLAY})

    def test_patch_differential_matches_isolated_probe(self):
        # 验收矩阵：P 阻 R1 不阻 R2；Q 阻两者（ordinary 策略）。
        self.assertEqual(rr.patch_matrix(self.db, 'R1')['ordinary'],
                         {'none': 'attack_reproduced', 'P': 'attack_blocked',
                          'Q': 'attack_blocked'})
        self.assertEqual(rr.patch_matrix(self.db, 'R2')['ordinary'],
                         {'none': 'attack_reproduced', 'P': 'attack_reproduced',
                          'Q': 'attack_blocked'})
        # research_release 的具体输入实验必须与现有 poison_probe 口径一致。
        for subject in ('R1', 'R2'):
            for level in ('none', 'P', 'Q'):
                out = rr.reproduce(self.db, subject, level, 'ordinary')
                self.assertTrue(out['probe_consistent'], out)
                self.assertEqual(out['decision'], out['probe_decision'])

    def test_concrete_r1_input_really_crosses_name_admission_gates(self):
        ev = rr.real_admission_evidence()
        # 具体伪造来源事件确实被真实 name.py 接受（来源校验只是标签相等）。
        self.assertEqual(ev['r1_forged_source_answer'], 'answer_accepted')
        # 对照：错误来源标签 / 旧代次仍被真实闸门拒绝。
        self.assertEqual(ev['wrong_label_source'], 'untrusted_resolver')
        self.assertEqual(ev['stale_generation'], 'stale_dns_answer')

    def test_concrete_inputs_cross_named_source_and_generation_gates(self):
        r1 = rr.reproduce(self.db, 'R1', 'none', 'ordinary')
        self.assertEqual(r1['decision'], 'attack_reproduced')
        self.assertIn('source_provenance', r1['crossed_gates'])
        self.assertIn('generation_watermark', r1['crossed_gates'])
        # P 在来源闸门拦截，R1 不再成功。
        self.assertEqual(rr.reproduce(self.db, 'R1', 'P')['decision'],
                         'attack_blocked')

        r2 = rr.reproduce(self.db, 'R2', 'none', 'ordinary')
        self.assertEqual(r2['decision'], 'attack_reproduced')
        self.assertIn('generation_freshness_binding', r2['crossed_gates'])
        # R2 带合法来源证明，所以 P 下放行；Q 的新鲜性绑定才阻断。
        self.assertEqual(rr.reproduce(self.db, 'R2', 'P')['decision'],
                         'attack_reproduced')
        blocked_q = rr.reproduce(self.db, 'R2', 'Q')
        self.assertEqual(blocked_q['decision'], 'attack_blocked')
        replay_step = next(s for s in blocked_q['steps']
                           if s.get('op') == 'cache_replay')
        self.assertEqual(replay_step['gate'], 'generation_freshness_binding')

    # ---- 3：供应商更早的超时故障单 --------------------------------------

    def test_vendor_timeout_ticket_is_prior_art_not_absorption(self):
        probe = rr.probe_vendor_ticket(self.db, 'VENDOR-OLD-TIMEOUT')
        self.assertEqual(probe['decision'], 'timeout_unchanged')
        self.assertEqual(set(probe['matrix'].values()), {'timeout'})
        # 故障单不在可运行报告账中，根因分组只有 R1 族与 R2。
        report_ids = {r['id'] for r in rr.existing_reports(self.db)}
        self.assertEqual(report_ids, {'R1', 'R2'})
        subjects = {s for g in rr.root_cause_groups(self.db) for s in g['subjects']}
        self.assertNotIn('VENDOR-OLD-TIMEOUT', subjects)
        summary = rr.clearance_matrix(self.db)
        self.assertEqual(summary['prior_art_tickets'][0]['symptom'], 'timeout')

    # ---- 4：补丁 Q 在 strict_legacy 正常答案上的回归 ----------------------

    def test_q_rejects_normal_answer_on_strict_legacy(self):
        normal = rr.reproduce(self.db, 'NORMAL-STRICT', 'Q', 'strict_legacy')
        self.assertEqual(normal['decision'], 'normal_answer_rejected')
        self.assertEqual(
            rr.reproduce(self.db, 'NORMAL-STRICT', 'P', 'strict_legacy')['decision'],
            'answer_accepted')
        self.assertEqual(
            rr.reproduce(self.db, 'NORMAL-STRICT', 'none', 'strict_legacy')['decision'],
            'answer_accepted')
        # 与现有探针的字面行为一致。
        self.assertEqual(probe_evaluate(self.db, 'R2', 'Q', 'strict_legacy'),
                         'normal_answer_rejected')
        snap = rr.exposure_snapshot(self.db)
        self.assertTrue(snap['q_regression_present'])
        self.assertTrue(snap['q_must_not_be_blanket_released'])

    # ---- 5：可逆真实租户查询 vs 最小外发证据 ------------------------------

    REAL_QUERY = "tenant=acme; SELECT account,email FROM customers WHERE id=4242"
    SALT = 'ran-undisclosed-salt'

    def test_real_tenant_query_is_reversible_only_in_vault(self):
        rr.seal_query(self.db, 'qt-1', self.REAL_QUERY)
        back = rr.unseal_query(self.db, 'qt-1', role='auditor')
        self.assertEqual(back['decision'], 'unsealed')
        self.assertEqual(back['query'], self.REAL_QUERY)  # 确实可逆
        denied = rr.unseal_query(self.db, 'qt-1', role='anonymous_outbound')
        self.assertEqual(denied['decision'], 'access_denied')

    def test_outbound_evidence_keeps_versions_but_not_query(self):
        rr.seal_query(self.db, 'qt-2', self.REAL_QUERY)
        evidence = rr.minimal_evidence(
            self.REAL_QUERY, self.SALT,
            affected_versions='resolver >=4.0.0,<4.7.2',
            fixed_versions={'P': '4.7.2-source-attestation (R1 only)'})
        blob = json.dumps(evidence, ensure_ascii=False)
        self.assertNotIn(self.REAL_QUERY, blob)
        self.assertIn('affected_versions', evidence)
        self.assertEqual(len(evidence['query_fingerprint']), 64)
        self.assertEqual(rr.scan_outbound(evidence, self.REAL_QUERY), [])

    def test_advisory_blocks_real_query_and_attack_recipe(self):
        evidence = rr.minimal_evidence(self.REAL_QUERY, self.SALT, '>=4 <4.7.2')
        ok = rr.draft_advisory(
            self.db, 'adv-safe', evidence=evidence,
            protective_guidance=['启用来源鉴别', '暂缓全量 Q，先验证 strict_legacy'],
            secret_query=self.REAL_QUERY)
        self.assertEqual(ok['decision'], 'advisory_drafted')
        leaked = rr.draft_advisory(
            self.db, 'adv-leak', body={'copy_of_query': self.REAL_QUERY},
            secret_query=self.REAL_QUERY)
        self.assertEqual(leaked['decision'], 'unsafe_content_blocked')
        recipe = rr.draft_advisory(
            self.db, 'adv-recipe',
            body={'attack_steps': [{'op': 'observe', 'source': 'src-main'}]})
        self.assertEqual(recipe['decision'], 'unsafe_content_blocked')

    # ---- 6：私下披露证据 / 盐复用可改判 ----------------------------------

    def test_signing_times_alone_do_not_prove_independence(self):
        status = rr.submission_independence(self.db)
        self.assertTrue(status['distinct_signed_timestamps'])
        self.assertIsNone(status['research_process_independent'])
        self.assertIn('unverified', status['status'])

    def test_salt_reuse_proof_reclassifies_r2_and_recomputes(self):
        plaintext = 'private-canary-shared-only-in-disclosure'
        fp = rr.hmac_fingerprint(plaintext, self.SALT)
        # R2 材料中出现了用冉的未公开盐制作的指标。
        rr.add_indicator(self.db, 'ind-r2-salt', 'R2', fp, salt_id='salt-ran')

        # 伪造的证明必须被拒绝且不改判。
        bad = rr.present_salt_proof(
            self.db, 'find-bad', 'R2', 'R1', 'salt-ran', plaintext,
            presented_fingerprint='0' * 64)
        self.assertEqual(bad['decision'], 'salt_proof_rejected')
        self.assertEqual(rr.derivation_status(self.db, 'R2')['state'], 'rejected')

        good = rr.present_salt_proof(
            self.db, 'find-good', 'R2', 'R1', 'salt-ran', plaintext)
        self.assertEqual(good['decision'], 'salt_proof_confirmed')
        status = rr.submission_independence(self.db)
        self.assertFalse(status['research_process_independent'])
        self.assertEqual(status['status'], 'derivative_use_confirmed')

        # 公开边界：缺少冉对派生盐材料的追加同意时，R2 检测方法不可发表。
        boundary = rr.public_boundary(self.db, joint=True)
        self.assertFalse(boundary['joint_detection_allowed'])
        # 付款义务：R2 临时报酬冻结为派生待清算。
        obl = rr.recompute_obligations(self.db)
        r2_award = next(a for a in obl['awards'].values() if a['report'] == 'R2')
        self.assertTrue(r2_award['derivative_hold'])
        self.assertEqual(r2_award['payable_now'], 0)

        # 拿到追加同意后，公开边界重新允许。
        rr.grant_publication_consent(
            self.db, 'consent-derived', 'pub-x', 'ran',
            scope='derived_salt_material')
        self.assertTrue(rr.public_boundary(self.db, joint=True)
                        ['joint_detection_allowed'])

    # ---- 7：付款退票 / 奖项撤销 ------------------------------------------

    def test_provisional_award_is_30_and_requires_report(self):
        with tempfile.TemporaryDirectory() as folder:
            db = connect(str(Path(folder) / 's.sqlite'))
            self.assertEqual(
                provisional_award(db, 'a', 'missing', 10)['decision'], 'unavailable')
            submit(db, 'R1', 'ran', 'z', 'h', 3)
            self.assertEqual(provisional_award(db, 'a', 'R1', 10)['amount'], 30)
            db.close()

    def test_bounced_bank_item_means_researcher_not_paid(self):
        rr.create_obligation(self.db, 'obl-w', 'wen', 'license', 100)
        pay = rr.initiate_payment(self.db, 'pay-1', 'wen', 100, 'BANK-1',
                                  obligation_id='obl-w')
        self.assertFalse(pay['paid'])
        self.assertEqual(
            rr.settle_payment(self.db, 'pay-1', None)['decision'],
            'bank_evidence_required')
        settled = rr.settle_payment(self.db, 'pay-1', {'trace': 'bank-tx-9'})
        self.assertTrue(settled['paid'])
        self.assertTrue(rr.payment_view(self.db, 'pay-1')['paid'])
        bounced = rr.bounce_payment(self.db, 'pay-1', 'insufficient account info')
        self.assertFalse(bounced['paid'])
        self.assertFalse(bounced['researcher_paid'])
        view = rr.payment_view(self.db, 'pay-1')
        self.assertEqual(view['state'], 'bounced')
        self.assertFalse(view['paid'])
        self.assertEqual(rr.payment_totals(self.db)['wen']['paid'], 0)
        self.assertEqual(rr.payment_totals(self.db)['wen']['bounced'], 100)
        # 退票把义务重新打开，不能记作已清偿。
        state = rr.one(self.db, 'SELECT state FROM rr_obligations WHERE id=?',
                       ('obl-w',))['state']
        self.assertEqual(state, 'outstanding')

    def test_revoked_award_blocks_new_payout_but_not_delivered_notice(self):
        rr.draft_advisory(self.db, 'adv-1', title='protective')
        rr.deliver_advisory(self.db, 'adv-1')
        rev = rr.revoke_award(self.db, 'award-r1', 'attribution dispute')
        self.assertEqual(rev['decision'], 'award_revoked')
        again = rr.revoke_award(self.db, 'award-r1')
        self.assertEqual(again['decision'], 'already_revoked')
        blocked = rr.initiate_payment(self.db, 'pay-x', 'ran', 30, 'REF-X',
                                      award_id='award-r1')
        self.assertEqual(blocked['decision'], 'award_revoked_payment_blocked')
        # 已送达公告不因为奖项撤销而消失或变回草稿。
        view = rr.advisory_view(self.db, 'adv-1')
        self.assertEqual(view['state'], 'delivered')
        self.assertTrue(view['delivered'])

    # ---- 8：公告送达后只能追加更正 ----------------------------------------

    def test_delivered_advisory_is_immutable_but_accepts_corrections(self):
        rr.draft_advisory(self.db, 'adv-2', title='DNS advisory',
                          body={'versions': '>=4 <4.7.2'})
        self.assertEqual(rr.deliver_advisory(self.db, 'adv-2')['decision'],
                         'advisory_delivered')
        self.assertEqual(rr.deliver_advisory(self.db, 'adv-2')['decision'],
                         'already_delivered')
        mutate = rr.mutate_delivered_advisory(self.db, 'adv-2', {'hacked': True})
        self.assertEqual(mutate['decision'], 'delivered_immutable')
        self.assertEqual(rr.advisory_view(self.db, 'adv-2')['body'],
                         {'versions': '>=4 <4.7.2'})
        self.assertEqual(rr.delete_advisory(self.db, 'adv-2')['decision'],
                         'delivered_immutable')

        c1 = rr.correct_advisory(self.db, 'corr-1', 'adv-2',
                                 {'add': 'Q 不应推送给 strict_legacy'},
                                 'Q 回归确认')
        c2 = rr.correct_advisory(self.db, 'corr-2', 'adv-2',
                                 {'add': 'P 回退会重新暴露 R1'}, 'rollback watch')
        self.assertEqual(c1['seq'], 1)
        self.assertEqual(c2['seq'], 2)
        view = rr.advisory_view(self.db, 'adv-2')
        self.assertEqual([c['seq'] for c in view['corrections']], [1, 2])
        self.assertTrue(view['delivered'])
        # 更正同样不能夹带真实查询。
        bad = rr.correct_advisory(
            self.db, 'corr-bad', 'adv-2', {'q': self.REAL_QUERY}, 'x',
            secret_query=self.REAL_QUERY)
        self.assertEqual(bad['decision'], 'unsafe_content_blocked')

    # ---- 两条合法交易路径及其差异 ----------------------------------------

    def test_path_a_separate_licenses_escrow_and_protective_notice(self):
        rr.record_employment_constraint(self.db, 'emp-ran', 'ran', 'ResolverCorp')
        held = rr.sign_internal_license(self.db, 'lic-ran', 'ran', 'R1', fee=120)
        self.assertEqual(held['decision'], 'employer_rights_uncleared')
        self.assertEqual(held['state'], 'held_employer_rights_uncleared')
        rr.waive_employment_constraint(self.db, 'emp-ran', 'waiver-ran-1')
        lic_ran = rr.sign_internal_license(self.db, 'lic-ran2', 'ran', 'R1', fee=120)
        self.assertEqual(lic_ran['decision'], 'license_effective')
        lic_wen = rr.sign_internal_license(self.db, 'lic-wen', 'wen', 'R2', fee=120)
        self.assertEqual(lic_wen['decision'], 'license_effective')
        rr.record_escrow(self.db, 'escrow-1', ['trace-r1', 'trace-r1b', 'trace-r2'])
        rr.draft_advisory(self.db, 'adv-a', title='防护通告（不含查询/步骤）')
        rr.deliver_advisory(self.db, 'adv-a')

        ready = rr.deal_a_readiness(self.db)
        self.assertTrue(ready['ready_to_contract'])
        self.assertTrue(ready['protective_advisory_delivered'])
        self.assertTrue(ready['exclusive_internal'])
        self.assertEqual(ready['internal_reproduction'], 'licensed_to_platform')
        self.assertIn('withheld', ready['publication'])

    def test_path_b_joint_publication_requires_consent_and_split(self):
        rr.create_publication(self.db, 'pub-1', deadline_at='2026-12-15T00:00:00Z')
        blocked = rr.publish_joint_detection(self.db, 'pub-1', total_amount=60)
        self.assertEqual(blocked['decision'], 'publication_conditions_unmet')

        rr.grant_publication_consent(self.db, 'con-ran', 'pub-1', 'ran')
        rr.grant_publication_consent(self.db, 'con-wen', 'pub-1', 'wen')
        rr.record_split(self.db, 'sp-ran', 'pub-1', 'ran', amount=36)
        rr.record_split(self.db, 'sp-wen', 'pub-1', 'wen', amount=24)
        mismatch = rr.publish_joint_detection(self.db, 'pub-1', total_amount=30)
        self.assertEqual(mismatch['decision'], 'publication_conditions_unmet')

        pub = rr.publish_joint_detection(self.db, 'pub-1', total_amount=60)
        self.assertEqual(pub['decision'], 'joint_detection_published')
        det = pub['detection']
        self.assertEqual(rr.scan_outbound(det), [])
        # 公开方法必须让客户自检 R2，且不含真实查询/攻击配方。
        self.assertIn('R2', det['id'])
        self.assertEqual(det['reverified_matrix']['P'], 'attack_reproduced')
        self.assertEqual(det['reverified_matrix']['Q'], 'attack_blocked')
        self.assertEqual(pub['internal_reproduction'], 'public_non_exclusive')
        blob = json.dumps(pub, ensure_ascii=False)
        self.assertNotIn(self.REAL_QUERY, blob)

    def test_paths_differ_on_publication_pay_and_exclusivity(self):
        # 路径 A 就绪：内部许可 + 保管。
        rr.sign_internal_license(self.db, 'la1', 'ran', 'R1')
        rr.sign_internal_license(self.db, 'la2', 'wen', 'R2')
        rr.record_escrow(self.db, 'e1', ['trace-r1', 'trace-r2'])
        a = rr.deal_a_readiness(self.db)
        self.assertEqual(a['internal_reproduction'], 'licensed_to_platform')
        self.assertFalse(rr.public_boundary(self.db)['joint_detection_allowed'])

        # 路径 B 就绪后：公开、非独占。
        rr.create_publication(self.db, 'pb')
        rr.grant_publication_consent(self.db, 'cb1', 'pb', 'ran')
        rr.grant_publication_consent(self.db, 'cb2', 'pb', 'wen')
        rr.record_split(self.db, 'sb1', 'pb', 'ran', amount=30)
        rr.record_split(self.db, 'sb2', 'pb', 'wen', amount=30)
        b = rr.publish_joint_detection(self.db, 'pb', total_amount=60)
        self.assertEqual(b['decision'], 'joint_detection_published')
        self.assertEqual(b['internal_reproduction'], 'public_non_exclusive')

    # ---- P 回退重新暴露 + 通知补充不可改写历史 ----------------------------

    def test_p_rollback_reopens_exposure_and_needs_correction(self):
        rr.draft_advisory(self.db, 'adv-3', title='notice')
        rr.deliver_advisory(self.db, 'adv-3', at='2026-11-25T10:00:00Z')

        rr.set_patch_level(self.db, 'P')
        exposed_p = rr.exposure_snapshot(self.db)['exposed_subjects']
        self.assertEqual(exposed_p, ['R2'])  # P 下 R1/R1B 已阻断
        rollback = rr.rollback_patch(self.db, 'none', at='2026-11-26T10:00:00Z')
        self.assertIn('R1', rollback['exposure_reopened'])
        self.assertIn('R1B', rollback['exposure_reopened'])
        snap = rr.exposure_snapshot(self.db)
        self.assertEqual(set(snap['exposed_subjects']), {'R1', 'R1B', 'R2'})

        # 对已送达通知追加回退更正；旧通知与送达时间保持不变。
        rr.correct_advisory(self.db, 'corr-rb', 'adv-3',
                            {'warning': 'P 已回退，R1 重新暴露'},
                            'patch rollback', at='2026-11-26T11:00:00Z')
        view = rr.advisory_view(self.db, 'adv-3')
        self.assertEqual(view['delivered_at'], '2026-11-25T10:00:00Z')
        self.assertEqual(len(view['corrections']), 1)
        self.assertIn('R1', json.dumps(view['corrections'][0]))

    # ---- 事件总线幂等 & 裸 sqlite3 兼容 ----------------------------------

    def test_event_bus_is_idempotent_and_rejects_payload_conflict(self):
        first = rr.run(self.db, {'event_id': 'ev-1', 'op': 'set_patch',
                                 'level': 'P'})
        second = rr.run(self.db, {'event_id': 'ev-1', 'op': 'set_patch',
                                  'level': 'P'})
        self.assertEqual(first, second)
        conflict = rr.run(self.db, {'event_id': 'ev-1', 'op': 'set_patch',
                                    'level': 'Q'})
        self.assertEqual(conflict['decision'], 'event_identity_conflict')

    def test_works_with_plain_sqlite_connection(self):
        db = sqlite3.connect(':memory:')  # 与 poison seed 相同的裸连接
        rr.seed_standard_case(db)
        self.assertEqual(
            rr.reproduce(db, 'R1', 'P', 'ordinary')['decision'], 'attack_blocked')
        self.assertEqual(
            rr.probe_vendor_ticket(db, 'VENDOR-OLD-TIMEOUT')['decision'],
            'timeout_unchanged')
        # 关闭重开（这里用临时文件验证真实提交持久化）。
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / 'raw.sqlite')
            fdb = sqlite3.connect(path)
            rr.seed_standard_case(fdb)
            fdb.close()
            fdb2 = sqlite3.connect(path)
            self.assertTrue(rr.same_root_cause(fdb2, 'R1', 'R1B'))
            fdb2.close()
        db.close()

    def test_case_summary_is_coherent(self):
        summary = rr.case_summary(self.db)
        self.assertEqual(len(summary['reports']), 2)
        self.assertTrue(summary['root_cause_attribution']
                        ['dedup_by_summary_would_misattribute'])
        self.assertIn('deal_a_protective_license', summary)
        self.assertIn('obligations', summary)
        self.assertIn('clearance', summary)

    def test_customer_notice_and_receipt_are_usable_but_minimal(self):
        rr.seal_query(self.db, 'qt-9', self.REAL_QUERY)
        evidence = rr.minimal_evidence(self.REAL_QUERY, self.SALT, '>=4.0 <4.7.2')
        rr.draft_advisory(
            self.db, 'adv-render', title='解析投毒防护通告', evidence=evidence,
            protective_guidance=['开启来源鉴别', 'Q 暂缓 strict_legacy 全量'],
            secret_query=self.REAL_QUERY)
        rr.deliver_advisory(self.db, 'adv-render')
        rr.correct_advisory(self.db, 'c-render', 'adv-render',
                            {'add': '留意 P 回退'}, '运维补充')
        rendered = rr.render_customer_notice(
            self.db, 'adv-render', secret_query=self.REAL_QUERY)
        self.assertTrue(rendered['safe_to_send'])
        self.assertIn('解析投毒防护通告', rendered['text'])
        self.assertIn('>=4.0 <4.7.2', rendered['text'])
        self.assertIn('[更正 1]', rendered['text'])
        self.assertNotIn(self.REAL_QUERY, rendered['text'])

        receipt = rr.render_researcher_receipt(
            self.db, 'R1', secret_query=self.REAL_QUERY)
        self.assertTrue(receipt['safe_to_send'])
        self.assertIn('attack_blocked', receipt['text'])  # P/Q 矩阵
        self.assertNotIn(self.REAL_QUERY, receipt['text'])

    def test_clearance_matrix_maps_each_required_record(self):
        # 先行贡献（供应商单）
        rr.record_employment_constraint(self.db, 'e1', 'ran', 'Corp')
        rr.waive_employment_constraint(self.db, 'e1', 'w-1')
        rr.sign_internal_license(self.db, 'l1', 'ran', 'R1', fee=10)
        rr.sign_internal_license(self.db, 'l2', 'wen', 'R2', fee=10)
        rr.create_publication(self.db, 'pub-dl', deadline_at='2026-12-01')
        rr.initiate_payment(self.db, 'pay-dl', 'ran', 10, 'REF-DL')
        rr.settle_payment(self.db, 'pay-dl', {'bank': 'settled'})

        matrix = rr.clearance_matrix(self.db)
        self.assertTrue(matrix['prior_art_tickets'])  # 先行贡献
        ran = next(p for p in matrix['parties'] if p['party'] == 'ran')
        self.assertTrue(ran['employment_constraints'])  # 雇佣约束
        self.assertTrue(ran['licenses'])                # 内部使用许可
        self.assertTrue(ran['payments'])                # 实际付款凭据
        pub = rr.publication_readiness(self.db, 'pub-dl')
        self.assertEqual(pub['deadline_at'], '2026-12-01')  # 发表期限
        self.assertTrue(ran['payments'][0]['bank_evidence'])
        self.assertEqual(ran['payments'][0]['state'], 'settled')


if __name__ == '__main__':
    unittest.main()
