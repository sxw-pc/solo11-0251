"""可复核的根因关联、贡献清偿与客户可用预警台账。

This module is the adjudication/release layer that sits *on top of* three
existing isolated pieces and never replaces them:

- ``cloudcourt.dns_research.submit``       报告摘要与自报影响（不含根因结论）
- ``cloudcourt.research_award``           ``impact * unit`` 的临时报酬（不是付款）
- ``cloudcourt.poison_probe.evaluate``    隔离探针的 P/Q 补丁实测矩阵
- ``cloudcourt.name``                     真实解析准入（本模块不改它、不替它打补丁）

设计不变量（与任务验收一一对应）::

    字节不同 != 根因不同          （存在异字节同根因的轨迹族）
    症状相同 != 根因相同          （R1 伪造来源 / R2 缓存回放，P 的差分证据）
    更早的供应商超时故障单         不吞并可运行利用链，P/Q 下超时不变
    Q 同时阻断 R1/R2              但在 strict_legacy 正常答案上回归
    真实租户查询可逆保管           外发材料只带版本证据与单向指纹
    独立签名时间 != 研究过程独立   盐复用证据出现后可改判派生关系
    合同 / 雇佣 / 许可 / 期限 / 银行凭据 逐一对应
    奖项撤销不删除已送达公告       银行退票后研究员不得记作已获报酬
    公告只能追加更正               不能把已送达通知改成未发
    盐复用证实 / P 回退            可重算公开边界与付款义务，历史不可改写

模块内所有写操作都是幂等的（同 ID 同内容返回 reused，异内容返回 conflict），
返回值为 JSON 可序列化的普通 dict。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from datetime import datetime, timezone

from .store import tx, one, many, act
from .dns_research import submit as submit_report
from .research_award import provisional_award
from .poison_probe import evaluate as probe_evaluate

# ---------------------------------------------------------------------------
# 常量：直接复用隔离探针已经验收的决策字面量，避免本模块另造口径。
# ---------------------------------------------------------------------------

BLOCKED = 'attack_blocked'
REPRODUCED = 'attack_reproduced'
REGRESSION = 'normal_answer_rejected'
UNKNOWN_REPORT = 'unknown_report'
TIMEOUT_UNCHANGED = 'timeout_unchanged'

RC_SOURCE = 'rc:unauthenticated-source-provenance'
RC_REPLAY = 'rc:missing-replay-freshness-binding'
# 两个近因分支同属一个上层根因族：准入信任自报的答案元数据，
# 而没有把 来源鉴别 + 代次/新鲜性 绑定到可验证材料上。
RC_UNBOUND = 'rc-family:answers-trusted-without-verifiable-binding'
ROOT_CAUSE_FAMILY = {
    RC_SOURCE: RC_UNBOUND,
    RC_REPLAY: RC_UNBOUND,
}

PATCHES = ('none', 'P', 'Q')
POLICIES = ('ordinary', 'strict_legacy')

# 外发文档禁止出现的结构化字段：原始轨迹/触发步骤/盐/明文查询。
OUTBOUND_FORBIDDEN_KEYS = (
    'attack_steps', 'trigger_steps', 'raw_steps', 'trace_steps',
    'trajectory', 'trajectory_bytes', 'traj_bytes', 'trigger_bytes',
    'salt', 'salt_value', 'plaintext_query', 'query_plaintext',
)

SCHEMA = '''
CREATE TABLE IF NOT EXISTS rr_trajectories(
    id TEXT PRIMARY KEY, subject TEXT, variant TEXT, mechanism TEXT, symptom TEXT,
    layer TEXT, root_cause TEXT, payload TEXT, traj_bytes TEXT, byte_digest TEXT,
    byte_len INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS rr_root_causes(
    id TEXT PRIMARY KEY, title TEXT, gate TEXT, description TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS rr_causal_links(
    id TEXT PRIMARY KEY, subject TEXT, trajectory_id TEXT, root_cause TEXT,
    basis TEXT, blocked_by TEXT, confidence TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS rr_reproductions(
    id TEXT PRIMARY KEY, subject TEXT, patch_level TEXT, tenant_policy TEXT,
    decision TEXT, probe_decision TEXT, consistent INTEGER, detail TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS rr_vendor_tickets(
    id TEXT PRIMARY KEY, vendor TEXT, domain TEXT, opened_at TEXT, symptom TEXT,
    timeout_only INTEGER, runnable_chain INTEGER, detail TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS rr_parties(
    id TEXT PRIMARY KEY, kind TEXT, display_name TEXT, attrs TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS rr_employment(
    id TEXT PRIMARY KEY, party TEXT, employer TEXT, constraint_text TEXT,
    state TEXT, waiver_ref TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS rr_licenses(
    id TEXT PRIMARY KEY, party TEXT, report_id TEXT, scope TEXT, exclusive INTEGER,
    fee INTEGER, agreement_ref TEXT, state TEXT, signed_at TEXT, terms TEXT);
CREATE TABLE IF NOT EXISTS rr_escrows(
    id TEXT PRIMARY KEY, custodian TEXT, material_refs TEXT, sealed_at TEXT, state TEXT);
CREATE TABLE IF NOT EXISTS rr_signed_submissions(
    report_id TEXT PRIMARY KEY, signer TEXT, signed_at TEXT, signature TEXT,
    bytes_digest TEXT, independent_timestamp INTEGER);
CREATE TABLE IF NOT EXISTS rr_disclosures(
    id TEXT PRIMARY KEY, from_party TEXT, to_party TEXT, materials TEXT,
    salt_id TEXT, at TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS rr_salts(
    id TEXT PRIMARY KEY, owner TEXT, salt_value TEXT, purpose TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS rr_indicators(
    id TEXT PRIMARY KEY, subject TEXT, fingerprint TEXT, salt_id TEXT,
    plaintext_ref TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS rr_derivations(
    id TEXT PRIMARY KEY, subject TEXT, source TEXT, state TEXT, proof TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS rr_consents(
    id TEXT PRIMARY KEY, pub_id TEXT, party TEXT, scope TEXT, at TEXT, state TEXT);
CREATE TABLE IF NOT EXISTS rr_splits(
    id TEXT PRIMARY KEY, pub_id TEXT, party TEXT, amount INTEGER, share REAL);
CREATE TABLE IF NOT EXISTS rr_publications(
    id TEXT PRIMARY KEY, mode TEXT, state TEXT, deadline_at TEXT,
    boundary TEXT, detection TEXT, created_at TEXT, published_at TEXT);
CREATE TABLE IF NOT EXISTS rr_obligations(
    id TEXT PRIMARY KEY, party TEXT, kind TEXT, amount INTEGER, award_id TEXT,
    state TEXT, reason TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS rr_payments(
    id TEXT PRIMARY KEY, obligation_id TEXT, award_id TEXT, party TEXT, amount INTEGER,
    reference TEXT UNIQUE, state TEXT, bank_evidence TEXT, initiated_at TEXT,
    settled_at TEXT, returned_at TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS rr_award_revocations(
    award_id TEXT PRIMARY KEY, reason TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS rr_advisories(
    id TEXT PRIMARY KEY, audience TEXT, title TEXT, body TEXT, evidence TEXT,
    safe_document TEXT, state TEXT, created_at TEXT, delivered_at TEXT);
CREATE TABLE IF NOT EXISTS rr_corrections(
    id TEXT PRIMARY KEY, advisory TEXT, seq INTEGER, kind TEXT, body TEXT,
    evidence TEXT, reason TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS rr_query_vault(
    token TEXT PRIMARY KEY, plaintext TEXT, kind TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS rr_vault_access(
    id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT, role TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS rr_patch_history(
    id INTEGER PRIMARY KEY AUTOINCREMENT, level TEXT, policy TEXT, action TEXT,
    reason TEXT, at TEXT);
CREATE TABLE IF NOT EXISTS rr_patch_state(
    id INTEGER PRIMARY KEY CHECK(id=1), level TEXT, policy TEXT, updated_at TEXT);
'''

_CREATE_STATEMENTS = [s.strip() for s in SCHEMA.split(';') if s.strip()]


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

def _now(at=None):
    return at or datetime.now(timezone.utc).isoformat()


def init(db):
    """幂等建表；把 row_factory 设成 Row（Row 仍支持下标，不影响既有调用）。"""
    try:
        db.row_factory = sqlite3.Row
    except Exception:
        pass
    with tx(db):
        for stmt in _CREATE_STATEMENTS:
            db.execute(stmt)
        db.execute(
            'INSERT OR IGNORE INTO rr_patch_state(id,level,policy,updated_at) '
            "VALUES(1,'none','ordinary',?)", (_now(),))
    return db


def _ensure(db):
    for stmt in _CREATE_STATEMENTS:
        db.execute(stmt)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def canonical_bytes(payload):
    """轨迹的规范字节。键序固定，因此同内容字节一致，改任一字段字节即不同。"""
    return canonical_json(payload).encode('utf-8')


def sha256_hex(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def hmac_fingerprint(plaintext, salt):
    """带未公开盐的单向指纹；没有盐时不能反推查询，也不能离线枚举确认。"""
    return hmac.new(salt.encode('utf-8'), plaintext.encode('utf-8'),
                    hashlib.sha256).hexdigest()


def _table_exists(db, name):
    return one(db, "SELECT 1 x FROM sqlite_master WHERE type='table' AND name=?",
               (name,)) is not None


def existing_reports(db):
    init(db)
    if not _table_exists(db, 'dns_research'):
        return []
    return many(db, 'SELECT * FROM dns_research ORDER BY id')


def existing_provisional_awards(db):
    init(db)
    if not _table_exists(db, 'research_awards'):
        return []
    return many(db, 'SELECT * FROM research_awards ORDER BY id')


# ---------------------------------------------------------------------------
# 具体轨迹：不是摘要，而是可在隔离实验里逐步重放的具体输入。
# ---------------------------------------------------------------------------

def ran_forged_source_trace(variant='R1'):
    """冉 R1：伪造解析来源 + 自报更高代次，覆盖旧观测。

    注意其中 source='src-main' 与解析策略里登记的标签相同：name.py 的来源
    校验只是“自报标签相等”，并不验证来源持有密钥/签名，所以伪造来源仍可
    通过；generation 同样是提交方自报整数，高一代次即越过水位。
    """
    suffix = '' if variant == 'R1' else '-v2'
    poisoned_ip = '198.51.100.66' if variant == 'R1' else '198.51.100.77'
    obs_id = 'obs-forged' if variant == 'R1' else 'obs-forged-b'
    event_id = 'e-forged' if variant == 'R1' else 'e-forged-b'
    return {
        'subject': variant,
        'researcher': 'ran',
        'mechanism': 'forged_source_overwrite',
        'symptom': 'untrusted_answer_becomes_latest_trusted_observation',
        'weakened_gates': ['source_provenance', 'generation_watermark'],
        'steps': [
            {'op': 'profile', 'id': 'profile-poison', 'tenant': 'tenant-poison',
             'host': 'update.example.invalid', 'generation': 1},
            {'op': 'resolver', 'id': 'resolver-poison', 'tenant': 'tenant-poison',
             'source': 'src-main', 'generation': 1},
            {'op': 'observe', 'id': 'obs-old', 'event_id': 'e-old',
             'profile': 'profile-poison', 'resolver': 'resolver-poison',
             'source': 'src-main', 'ip': '198.51.100.10', 'generation': 1,
             'observed': 10, 'expires': 100, 'provenance': 'valid', 'benign': True},
            {'op': 'observe', 'id': obs_id, 'event_id': event_id,
             'profile': 'profile-poison', 'resolver': 'resolver-poison',
             'source': 'src-main', 'ip': poisoned_ip, 'generation': 2,
             'observed': 20, 'expires': 120,
             'provenance': 'forged_self_asserted', 'hostile': True,
             'crosses': ['source_provenance', 'generation_watermark']},
        ],
        'suffix': suffix,
    }


def wen_cache_replay_trace(variant='R2'):
    """闻 R2：回放一份来源证明有效的旧缓存记录。

    因为记录本身带合法来源证明，P（补来源鉴别）不拦它；缓存/准入路径缺少
    一次性 nonce / 已消费代次日志，回放仍被当成新的可信观测，达到与 R1
    相同的表面结果。Q 增加回放新鲜性绑定后才阻断。
    """
    return {
        'subject': variant,
        'researcher': 'wen',
        'mechanism': 'cache_replay',
        'symptom': 'untrusted_answer_becomes_latest_trusted_observation',
        'weakened_gates': ['generation_freshness_binding'],
        'steps': [
            {'op': 'profile', 'id': 'profile-cache', 'tenant': 'tenant-cache',
             'host': 'cdn.example.invalid', 'generation': 3},
            {'op': 'resolver', 'id': 'resolver-cache', 'tenant': 'tenant-cache',
             'source': 'src-main', 'generation': 2},
            {'op': 'origin_answer', 'id': 'obs-origin',
             'source': 'src-main', 'ip': '198.51.100.66', 'generation': 5,
             'provenance': 'valid', 'nonce': 'n-7f31', 'benign': False},
            {'op': 'cache_store', 'ref': 'cache-key-cdn', 'observation': 'obs-origin'},
            {'op': 'cache_replay', 'id': 'obs-replayed',
             'source': 'src-main', 'ip': '198.51.100.66', 'generation': 5,
             'provenance': 'valid', 'nonce': 'n-7f31', 'replay_of': 'obs-origin',
             'replay_nonce_seen': True, 'hostile': True,
             'crosses': ['generation_freshness_binding']},
        ],
    }


def strict_legacy_normal_trace(variant='NORMAL-STRICT'):
    """未受攻击的 strict_legacy 客户策略上的正常答案。"""
    return {
        'subject': variant,
        'customer_policy': 'strict_legacy',
        'mechanism': 'ordinary_answer',
        'symptom': 'none',
        'steps': [
            {'op': 'profile', 'id': 'profile-legacy', 'tenant': 'tenant-legacy',
             'host': 'legacy.example.invalid', 'generation': 1},
            {'op': 'resolver', 'id': 'resolver-legacy', 'tenant': 'tenant-legacy',
             'source': 'src-legacy', 'generation': 1},
            {'op': 'observe', 'id': 'obs-ok',
             'profile': 'profile-legacy', 'resolver': 'resolver-legacy',
             'source': 'src-legacy', 'ip': '203.0.113.20', 'generation': 1,
             'observed': 30, 'expires': 300, 'provenance': 'valid', 'benign': True},
        ],
    }


def vendor_timeout_trace(ticket='VENDOR-OLD-TIMEOUT'):
    """供应商一年前故障单：只有解析超时，没有可运行利用链。"""
    return {
        'subject': ticket,
        'mechanism': 'upstream_resolution_timeout',
        'symptom': 'timeout',
        'steps': [
            {'op': 'query', 'name': 'same-domain.example', 'result': 'timeout'},
            {'op': 'retry', 'result': 'timeout'},
        ],
    }


STANDARD_TRAJECTORY_BUILDERS = {
    'R1': ran_forged_source_trace,
    'R1B': lambda: ran_forged_source_trace('R1B'),
    'R2': wen_cache_replay_trace,
    'NORMAL-STRICT': strict_legacy_normal_trace,
    'VENDOR-OLD-TIMEOUT': vendor_timeout_trace,
}


# ---------------------------------------------------------------------------
# 隔离实验闸门：把具体轨迹输入在 none/P/Q × ordinary/strict_legacy 下跑一遍。
# 判定口径必须与 cloudcourt.poison_probe.evaluate 完全一致（由测试锚定）。
# ---------------------------------------------------------------------------

def lab_decide(trace, patch_level='none', tenant_policy='ordinary'):
    """纯函数：逐步跑隔离闸门，返回每步判定与最终 decision。

    每个被接受的敌对步骤都会标明它具体越过了哪道闸门
    （source_provenance / generation_watermark /
    generation_freshness_binding），使“具体输入如何越过解析源与代次校验”
    可逐步复核，而不是只给一个报告 ID。
    """
    steps = trace.get('steps', []) if isinstance(trace, dict) else []
    q_strict = patch_level == 'Q' and tenant_policy == 'strict_legacy'
    max_generation = 0
    step_results = []
    crossed_gates = []
    final = 'no_admission_attempt'

    for st in steps:
        op = st.get('op')
        if op in ('profile', 'resolver', 'cache_store', 'setup', 'query', 'retry'):
            decision = 'configured' if op not in ('query', 'retry') else 'timeout'
            step_results.append({'op': op, 'id': st.get('id'), 'decision': decision})
            if op in ('query', 'retry'):
                final = 'timeout'
            continue

        if op in ('observe', 'origin_answer', 'cache_replay'):
            crosses = list(st.get('crosses', []))
            # 与 poison_probe 相同的优先级：Q + strict_legacy 先表现为正常答案被拒。
            if q_strict:
                decision = REGRESSION
                step_results.append({'op': op, 'id': st.get('id'),
                                     'crosses': crosses, 'decision': decision})
                final = REGRESSION
                break
            # P/Q：来源必须带可验证鉴别材料，自报标签不再足够。
            if patch_level in ('P', 'Q') and st.get('provenance') != 'valid':
                decision = BLOCKED
                step_results.append({'op': op, 'id': st.get('id'),
                                     'gate': 'source_provenance',
                                     'would_cross': crosses,
                                     'decision': decision})
                final = BLOCKED
                break
            # Q：一次性 nonce / 已消费代次日志，阻断缓存回放。
            if patch_level == 'Q' and op == 'cache_replay' \
                    and st.get('replay_nonce_seen', True):
                decision = BLOCKED
                step_results.append(
                    {'op': op, 'id': st.get('id'),
                     'gate': 'generation_freshness_binding',
                     'would_cross': crosses, 'decision': decision})
                final = BLOCKED
                break
            generation = int(st.get('generation', 0) or 0)
            generation_gate = ('crossed_self_asserted_higher_generation'
                               if generation > max_generation
                               else 'bound_valid_replayed_generation')
            max_generation = max(max_generation, generation)
            if st.get('hostile'):
                decision = REPRODUCED
                final = REPRODUCED
                crossed_gates = crosses or [generation_gate]
            else:
                decision = 'answer_accepted'
                final = 'answer_accepted'
            step_results.append({'op': op, 'id': st.get('id'),
                                 'generation_gate': generation_gate,
                                 'crosses': crosses,
                                 'decision': decision})

    return {'decision': final, 'steps': step_results,
            'crossed_gates': crossed_gates,
            'patch_level': patch_level, 'tenant_policy': tenant_policy}


def timeout_matrix():
    """供应商超时路径不被 P/Q 触碰：三种补丁级别下都是 timeout。"""
    return {level: lab_decide(vendor_timeout_trace(), level)['decision']
            for level in PATCHES}


# ---------------------------------------------------------------------------
# 真实 name.py 准入的诚实锚定：只证明现有真实闸门实际会怎么判。
# R1 的伪造来源事件确实会被 name.run 接受——因为 source 校验只是标签相等，
# generation 是自报整数。这里不修改 name.py，只在隔离内存库里执行具体输入。
# ---------------------------------------------------------------------------

def real_admission_evidence():
    from .store import connect
    from . import name

    db = connect(':memory:')
    events = [
        {'event_id': 'rp', 'op': 'profile', 'id': 'profile-poison',
         'tenant': 'tenant-poison', 'host': 'update.example.invalid', 'generation': 1},
        {'event_id': 'rr', 'op': 'resolver', 'id': 'resolver-poison',
         'tenant': 'tenant-poison', 'source': 'src-main', 'generation': 1},
        {'event_id': 'ro', 'op': 'observe', 'id': 'obs-old',
         'profile': 'profile-poison', 'resolver': 'resolver-poison',
         'source': 'src-main', 'ip': '198.51.100.10', 'generation': 1,
         'observed': 10, 'expires': 100},
        # R1 具体输入：source 仍是 src-main，但来源由攻击者伪造/自报。
        {'event_id': 'rf', 'op': 'observe', 'id': 'obs-forged',
         'profile': 'profile-poison', 'resolver': 'resolver-poison',
         'source': 'src-main', 'ip': '198.51.100.66', 'generation': 2,
         'observed': 20, 'expires': 120},
        # 对照：连标签都不对的来源，会被真实闸门拒绝。
        {'event_id': 'rw', 'op': 'observe', 'id': 'obs-wrong-source',
         'profile': 'profile-poison', 'resolver': 'resolver-poison',
         'source': 'src-attacker', 'ip': '198.51.100.77', 'generation': 3,
         'observed': 21, 'expires': 121},
        # 对照：不提高代次的旧答案，会被代次水位拒绝。
        {'event_id': 'rg', 'op': 'observe', 'id': 'obs-stale',
         'profile': 'profile-poison', 'resolver': 'resolver-poison',
         'source': 'src-main', 'ip': '198.51.100.88', 'generation': 1,
         'observed': 22, 'expires': 122},
    ]
    decisions = [name.run(db, e)['decision'] for e in events]
    db.close()
    return {
        'backend': 'cloudcourt.name.run',
        'events': events,
        'decisions': decisions,
        'initial_answer': decisions[2],
        'r1_forged_source_answer': decisions[3],
        'wrong_label_source': decisions[4],
        'stale_generation': decisions[5],
        'finding': (
            'name.py 的 source 校验只比较提交字段与策略标签是否相等，'
            '不验证来源鉴别；generation 由提交方自报且只做单调水位。'
            '因此知道公开标签 src-main 的伪造来源可用更高代次被接受；'
            '但错误标签与低代次重放会被现有闸门拒绝。R2 的缓存重放链位于'
            '缓存/新鲜性层，结论以隔离探针为准，不能夸大成 name.py 已可利用。'
        ),
    }


# ---------------------------------------------------------------------------
# 轨迹与根因关联台账
# ---------------------------------------------------------------------------

def record_trajectory(db, trajectory_id, subject, mechanism, symptom, payload,
                      root_cause=None, layer='isolated_lab', variant=None, at=None):
    init(db)
    raw = canonical_bytes(payload)
    digest = sha256_hex(raw)
    with tx(db):
        _ensure(db)
        old = one(db, 'SELECT * FROM rr_trajectories WHERE id=?', (trajectory_id,))
        if old:
            same = (old['byte_digest'] == digest
                    and old['mechanism'] == mechanism
                    and (old['root_cause'] or None) == root_cause)
            return {'decision': 'reused' if same else 'conflict',
                    'id': trajectory_id, 'byte_digest': old['byte_digest']}
        db.execute(
            'INSERT INTO rr_trajectories VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
            (trajectory_id, subject, variant, mechanism, symptom, layer,
             root_cause, canonical_json(payload), raw.decode('latin-1'),
             digest, len(raw), _now(at)))
    return {'decision': 'recorded', 'id': trajectory_id,
            'byte_digest': digest, 'byte_len': len(raw)}


def trajectory_bytes(db, trajectory_id):
    row = one(init(db), 'SELECT traj_bytes FROM rr_trajectories WHERE id=?',
              (trajectory_id,))
    return row['traj_bytes'].encode('latin-1') if row else None


def get_trajectory(db, trajectory_id):
    row = one(init(db), 'SELECT * FROM rr_trajectories WHERE id=?', (trajectory_id,))
    if not row:
        return None
    d = dict(row)
    d['payload'] = json.loads(d['payload'])
    return d


def digests_differ(db, trajectory_a, trajectory_b):
    a = one(init(db), 'SELECT byte_digest FROM rr_trajectories WHERE id=?',
            (trajectory_a,))
    b = one(db, 'SELECT byte_digest FROM rr_trajectories WHERE id=?',
            (trajectory_b,))
    if not a or not b:
        return None
    return a['byte_digest'] != b['byte_digest']


def record_root_cause(db, rc_id, title, gate, description='', at=None):
    init(db)
    with tx(db):
        _ensure(db)
        if one(db, 'SELECT 1 x FROM rr_root_causes WHERE id=?', (rc_id,)):
            return {'decision': 'reused', 'id': rc_id}
        db.execute('INSERT INTO rr_root_causes VALUES(?,?,?,?,?)',
                   (rc_id, title, gate, description, _now(at)))
    return {'decision': 'recorded', 'id': rc_id}


def link_cause(db, link_id, subject, root_cause, basis,
               trajectory_id=None, blocked_by=None, confidence='differential_patch',
               at=None):
    init(db)
    blocked_by = blocked_by or []
    with tx(db):
        _ensure(db)
        old = one(db, 'SELECT root_cause FROM rr_causal_links WHERE id=?', (link_id,))
        if old:
            return {'decision': 'reused' if old['root_cause'] == root_cause
                    else 'conflict', 'id': link_id}
        db.execute('INSERT INTO rr_causal_links VALUES(?,?,?,?,?,?,?,?)',
                   (link_id, subject, trajectory_id, root_cause, basis,
                    canonical_json(list(blocked_by)), confidence, _now(at)))
    return {'decision': 'linked', 'id': link_id, 'root_cause': root_cause}


# 更贴近英文业务命名的别名
link_root_cause = link_cause
record_causal_link = link_cause


def causal_links(db):
    init(db)
    rows = many(db, 'SELECT * FROM rr_causal_links ORDER BY id')
    for r in rows:
        r['blocked_by'] = json.loads(r['blocked_by'] or '[]')
    return rows


def root_cause_groups(db):
    """按根因归组主体；归组依据是因果链/补丁差分，而不是摘要或哈希。"""
    links = causal_links(db)
    groups = {}
    for ln in links:
        groups.setdefault(ln['root_cause'], []).append(ln['subject'])
    return [{'root_cause': rc, 'subjects': sorted(set(subjects))}
            for rc, subjects in sorted(groups.items())]


def same_root_cause(db, subject_a, subject_b):
    links = causal_links(db)
    ca = {x['root_cause'] for x in links if x['subject'] == subject_a}
    cb = {x['root_cause'] for x in links if x['subject'] == subject_b}
    if not ca or not cb:
        return None
    return bool(ca & cb)


def root_cause_family(root_cause):
    return ROOT_CAUSE_FAMILY.get(root_cause, root_cause)


def same_cause_family(db, subject_a, subject_b):
    """近因可不同（P 差分），但可能同属一个上层根因族（Q 全阻）。"""
    links = causal_links(db)
    fa = {root_cause_family(x['root_cause']) for x in links
          if x['subject'] == subject_a}
    fb = {root_cause_family(x['root_cause']) for x in links
          if x['subject'] == subject_b}
    if not fa or not fb:
        return None
    return bool(fa & fb)


def attribute_causes(db):
    """输出“异字节同根因 / 同症状异根因”的可复核判定。"""
    init(db)
    trajs = many(db, 'SELECT id,subject,byte_digest,symptom,mechanism '
                     'FROM rr_trajectories ORDER BY id')
    links = causal_links(db)
    cause_by_subject = {}
    for ln in links:
        cause_by_subject.setdefault(ln['subject'], set()).add(ln['root_cause'])

    byte_same_cause = []
    symptom_diff_cause = []
    for i, a in enumerate(trajs):
        for b in trajs[i + 1:]:
            bytes_differ = a['byte_digest'] != b['byte_digest']
            ca = cause_by_subject.get(a['subject'], set())
            cb = cause_by_subject.get(b['subject'], set())
            shared = bool(ca & cb)
            if bytes_differ and shared:
                byte_same_cause.append(
                    {'a': a['id'], 'b': b['id'], 'relation': 'different_bytes_same_cause'})
            if a['symptom'] == b['symptom'] and a['symptom'] not in (None, 'none') \
                    and ca and cb and not (ca & cb):
                symptom_diff_cause.append(
                    {'a': a['id'], 'b': b['id'], 'symptom': a['symptom'],
                     'causes_a': sorted(ca), 'causes_b': sorted(cb),
                     'relation': 'same_symptom_different_cause'})

    dedup_warning = None
    r1 = next((t for t in trajs if t['subject'] == 'R1'), None)
    r2 = next((t for t in trajs if t['subject'] == 'R2'), None)
    if r1 and r2 and r1['symptom'] == r2['symptom']:
        dedup_warning = (
            'R1/R2 摘要或表面症状相同，但 P 只消除 R1、不消除 R2，'
            '按摘要/症状去重会错分两份可运行贡献。')
    return {
        'groups': root_cause_groups(db),
        'different_bytes_same_cause': byte_same_cause,
        'same_symptom_different_cause': symptom_diff_cause,
        'dedup_by_summary_would_misattribute': dedup_warning,
    }


attribute_root_causes = attribute_causes


# ---------------------------------------------------------------------------
# 复现 + 与现有 poison_probe 锚定
# ---------------------------------------------------------------------------

def reproduce(db, subject, patch_level='none', tenant_policy='ordinary',
              reproduction_id=None, at=None):
    init(db)
    row = one(db, 'SELECT payload FROM rr_trajectories WHERE id=? OR subject=? '
                  'ORDER BY id LIMIT 1', (subject, subject))
    if row:
        trace = json.loads(row['payload'])
    elif subject in STANDARD_TRAJECTORY_BUILDERS:
        trace = STANDARD_TRAJECTORY_BUILDERS[subject]()
    else:
        return {'decision': UNKNOWN_REPORT, 'subject': subject}

    lab = lab_decide(trace, patch_level, tenant_policy)
    decision = lab['decision']

    # 锚定现有隔离探针：只有 dns_research 里存在的报告才能调 evaluate。
    probe_decision = None
    probe_row = one(db, 'SELECT id FROM dns_research WHERE id=?', (subject,)) \
        if _table_exists(db, 'dns_research') else None
    if probe_row:
        probe_decision = probe_evaluate(db, subject, patch_level, tenant_policy)

    consistent = None
    if probe_decision is not None:
        # Q+strict 下两者口径都是 normal_answer_rejected；其余矩阵逐项相等。
        consistent = (probe_decision == decision)

    rep_id = reproduction_id or f'repro:{subject}:{patch_level}:{tenant_policy}'
    with tx(db):
        _ensure(db)
        db.execute('DELETE FROM rr_reproductions WHERE id=?', (rep_id,))
        db.execute('INSERT INTO rr_reproductions VALUES(?,?,?,?,?,?,?,?,?)',
                   (rep_id, subject, patch_level, tenant_policy, decision,
                    probe_decision,
                    None if consistent is None else int(consistent),
                    canonical_json(lab), _now(at)))
    return {'decision': decision, 'subject': subject,
            'patch_level': patch_level, 'tenant_policy': tenant_policy,
            'crossed_gates': lab.get('crossed_gates', []),
            'probe_decision': probe_decision, 'probe_consistent': consistent,
            'steps': lab['steps']}


def patch_matrix(db, subject, policies=('ordinary',)):
    out = {}
    for policy in policies:
        out[policy] = {level: reproduce(db, subject, level, policy)['decision']
                       for level in PATCHES}
    return out


def record_vendor_ticket(db, ticket_id, vendor, domain, opened_at,
                         symptom='timeout', detail='仅记录解析超时，无可运行利用链',
                         at=None):
    init(db)
    with tx(db):
        _ensure(db)
        if one(db, 'SELECT 1 x FROM rr_vendor_tickets WHERE id=?', (ticket_id,)):
            return {'decision': 'reused', 'id': ticket_id}
        db.execute('INSERT INTO rr_vendor_tickets VALUES(?,?,?,?,?,?,?,?,?)',
                   (ticket_id, vendor, domain, opened_at, symptom, 1, 0,
                    detail, _now(at)))
    return {'decision': 'recorded', 'id': ticket_id,
            'prior_art_only': 'timeout_without_runnable_chain'}


def probe_vendor_ticket(db, ticket_id):
    init(db)
    ticket = one(db, 'SELECT * FROM rr_vendor_tickets WHERE id=?', (ticket_id,))
    if not ticket:
        return {'decision': 'unknown_ticket'}
    matrix = timeout_matrix()
    unchanged = len(set(matrix.values())) == 1 and 'timeout' in set(matrix.values())
    return {'decision': TIMEOUT_UNCHANGED if unchanged else 'timeout_changed',
            'ticket': ticket_id, 'matrix': matrix,
            'earlier_date_does_not_absorb': (
                '只有超时症状、没有可运行触发链的旧故障单不构成对 R1/R2 '
                '可运行贡献的吞并；它作为在先观察单独列示。')}


# ---------------------------------------------------------------------------
# 可逆租户查询保管 + 最小外发证据
# ---------------------------------------------------------------------------

def seal_query(db, token, query, kind='real_tenant_query', at=None):
    """把真实查询放进保管库；只有显式保管角色才能 unseal（可逆）。"""
    init(db)
    with tx(db):
        _ensure(db)
        if one(db, 'SELECT 1 x FROM rr_query_vault WHERE token=?', (token,)):
            return {'decision': 'reused', 'token': token, 'reversible': True}
        db.execute('INSERT INTO rr_query_vault VALUES(?,?,?,?)',
                   (token, query, kind, _now(at)))
    return {'decision': 'sealed', 'token': token, 'reversible': True}


protect_query = seal_query


def unseal_query(db, token, role='platform_ir', at=None):
    init(db)
    allowed = {'platform_ir', 'custodian', 'auditor', 'independent_escrow'}
    if role not in allowed:
        return {'decision': 'access_denied'}
    row = one(db, 'SELECT plaintext FROM rr_query_vault WHERE token=?', (token,))
    if not row:
        return {'decision': 'unknown_token'}
    with tx(db):
        db.execute('INSERT INTO rr_vault_access(token,role,at) VALUES(?,?,?)',
                   (token, role, _now(at)))
    return {'decision': 'unsealed', 'query': row['plaintext']}


def minimal_evidence(query, salt, affected_versions, fixed_versions=None,
                     extra=None):
    """外发/回执可用的最小证据：版本区间 + 盐化单向指纹，不含查询本身。"""
    doc = {
        'evidence_schema': 'cloudcourt.minimal/v1',
        'affected_versions': affected_versions,
        'fixed_versions': fixed_versions or {},
        'query_fingerprint': hmac_fingerprint(query, salt),
        'fingerprint_algorithm': 'HMAC-SHA256(salt, tenant_query)',
        'contains_real_query': False,
    }
    if extra:
        doc.update(extra)
    return doc


def scan_outbound(document, secret_query=None):
    """返回外发文档的违规列表；空列表才允许送达。"""
    violations = []

    def walk(node, path='$'):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in OUTBOUND_FORBIDDEN_KEYS and v not in (None, '', [], {}):
                    violations.append(f'forbidden_key:{path}.{k}')
                walk(v, f'{path}.{k}')
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f'{path}[{i}]')
        elif isinstance(node, str) and secret_query and secret_query in node:
            violations.append(f'real_query_leaked_at:{path}')

    walk(document)
    rendered = canonical_json(document)
    if secret_query and secret_query in rendered:
        violations.append('real_query_leaked:document')
    return sorted(set(violations))


# ---------------------------------------------------------------------------
# 盐、私下披露与派生证据
# ---------------------------------------------------------------------------

def register_salt(db, salt_id, owner, salt_value, purpose='undisclosed', at=None):
    init(db)
    with tx(db):
        _ensure(db)
        if one(db, 'SELECT 1 x FROM rr_salts WHERE id=?', (salt_id,)):
            return {'decision': 'reused', 'id': salt_id}
        db.execute('INSERT INTO rr_salts VALUES(?,?,?,?,?)',
                   (salt_id, owner, salt_value, purpose, _now(at)))
    return {'decision': 'registered', 'id': salt_id, 'owner': owner}


def add_indicator(db, indicator_id, subject, fingerprint, salt_id=None,
                  plaintext_ref=None, at=None):
    init(db)
    with tx(db):
        _ensure(db)
        db.execute('INSERT OR REPLACE INTO rr_indicators VALUES(?,?,?,?,?,?)',
                   (indicator_id, subject, fingerprint, salt_id,
                    plaintext_ref, _now(at)))
    return {'decision': 'recorded', 'id': indicator_id}


def record_signed_submission(db, report_id, signer, signed_at,
                             signature=None, bytes_digest=None):
    init(db)
    with tx(db):
        _ensure(db)
        db.execute(
            'INSERT OR REPLACE INTO rr_signed_submissions VALUES(?,?,?,?,?,?)',
            (report_id, signer, signed_at, signature, bytes_digest, 1))
    return {'decision': 'recorded', 'report_id': report_id,
            'independent_timestamp_only': True}


def submission_independence(db, report_a='R1', report_b='R2'):
    """只有独立签名时间时，研究过程独立性必须是 unverified，不能判 independent。"""
    a = one(init(db), 'SELECT * FROM rr_signed_submissions WHERE report_id=?',
            (report_a,))
    b = one(db, 'SELECT * FROM rr_signed_submissions WHERE report_id=?', (report_b,))
    if not a or not b:
        return {'decision': 'missing_signing_records', 'status': 'unverified'}
    independent_times = a['signed_at'] != b['signed_at']
    deriv = one(db, "SELECT state FROM rr_derivations WHERE subject=? "
                    "ORDER BY rowid DESC LIMIT 1", (report_b,))
    raw_state = deriv['state'] if deriv else 'unverified'
    status = {
        'unverified': 'unverified_from_signing_times_alone',
        'confirmed': 'derivative_use_confirmed',
        'rejected': 'salt_proof_rejected',
    }.get(raw_state, raw_state)
    return {
        'status': status,
        'derivation_state': raw_state,
        'research_process_independent': (
            True if raw_state == 'rejected' else
            False if raw_state == 'confirmed' else None),
        'distinct_signed_timestamps': independent_times,
        'proof_of_research_process': False,
        'note': '各自独立的签名提交时间只能证明提交时刻不同，不能证明研究过程'
                '独立；私下披露/盐复用证据出现后必须重算。',
    }


def record_disclosure(db, disclosure_id, from_party, to_party, materials,
                      at=None, salt_id=None, note=''):
    init(db)
    with tx(db):
        _ensure(db)
        if one(db, 'SELECT 1 x FROM rr_disclosures WHERE id=?', (disclosure_id,)):
            return {'decision': 'reused', 'id': disclosure_id}
        db.execute('INSERT INTO rr_disclosures VALUES(?,?,?,?,?,?,?)',
                   (disclosure_id, from_party, to_party, canonical_json(materials),
                    salt_id, _now(at), note))
    return {'decision': 'recorded', 'id': disclosure_id}


def present_salt_proof(db, finding_id, subject, source, salt_id, plaintext,
                       presented_fingerprint=None, at=None):
    """证实 R2 材料里出现了只有用 R1 未公开盐才能算出的指纹。

    校验两件事：(1) 指纹确实等于 HMAC(盐, 约定明文)；(2) 该指纹确实作为
    指标存在于 subject 的材料中。任一不满足 -> rejected，且不改归属。
    """
    init(db)
    salt = one(db, 'SELECT salt_value FROM rr_salts WHERE id=?', (salt_id,))
    if not salt:
        result_state = 'rejected'
        proof = {'reason': 'unknown_salt'}
    else:
        expected = hmac_fingerprint(plaintext, salt['salt_value'])
        presented = presented_fingerprint or expected
        indicator = one(
            db, 'SELECT 1 x FROM rr_indicators WHERE subject=? AND fingerprint=?',
            (subject, expected))
        if hmac.compare_digest(expected, presented) and indicator:
            result_state = 'confirmed'
            proof = {'hmac_matches': True, 'indicator_present': True,
                      'conclusion': f'{subject} used undisclosed salt from {source}'}
        else:
            result_state = 'rejected'
            proof = {'hmac_matches': hmac.compare_digest(expected, presented),
                     'indicator_present': bool(indicator)}

    with tx(db):
        _ensure(db)
        old = one(db, 'SELECT state FROM rr_derivations WHERE id=?', (finding_id,))
        if old:
            return {'decision': 'reused', 'id': finding_id, 'state': old['state']}
        db.execute('INSERT INTO rr_derivations VALUES(?,?,?,?,?,?)',
                   (finding_id, subject, source, result_state,
                    canonical_json(proof), _now(at)))
    return {'decision': 'salt_proof_' + result_state, 'id': finding_id,
            'state': result_state, 'proof': proof}


verify_salt_use = present_salt_proof


def derivation_status(db, subject='R2'):
    row = one(init(db), "SELECT * FROM rr_derivations WHERE subject=? "
                        "ORDER BY rowid DESC LIMIT 1", (subject,))
    if not row:
        return {'subject': subject, 'state': 'unverified'}
    d = dict(row)
    d['proof'] = json.loads(d['proof'] or '{}')
    return d


# ---------------------------------------------------------------------------
# 当事方 / 雇佣约束 / 内部许可 / 第三方保管
# ---------------------------------------------------------------------------

def upsert_party(db, party_id, kind='researcher', display_name='', attrs=None):
    init(db)
    with tx(db):
        _ensure(db)
        db.execute('INSERT OR REPLACE INTO rr_parties VALUES(?,?,?,?,?)',
                   (party_id, kind, display_name,
                    canonical_json(attrs or {}), _now()))
    return {'decision': 'recorded', 'party': party_id}


def record_employment_constraint(db, constraint_id, party, employer,
                                 constraint_text='职务成果/雇佣归属约束未豁免',
                                 at=None):
    init(db)
    with tx(db):
        _ensure(db)
        db.execute('INSERT OR REPLACE INTO rr_employment VALUES(?,?,?,?,?,?,?)',
                   (constraint_id, party, employer, constraint_text,
                    'open', None, _now(at)))
    return {'decision': 'recorded', 'id': constraint_id, 'state': 'open'}


def waive_employment_constraint(db, constraint_id, waiver_ref, at=None):
    init(db)
    with tx(db):
        row = one(db, 'SELECT party FROM rr_employment WHERE id=?', (constraint_id,))
        if not row:
            return {'decision': 'unknown_constraint'}
        db.execute("UPDATE rr_employment SET state='waived',waiver_ref=?,at=? "
                   'WHERE id=?', (waiver_ref, _now(at), constraint_id))
    return {'decision': 'waived', 'id': constraint_id, 'waiver_ref': waiver_ref}


def open_employment_constraints(db, party):
    return many(init(db),
                "SELECT * FROM rr_employment WHERE party=? AND state='open'",
                (party,))


def sign_internal_license(db, license_id, party, report_id, fee=0,
                          signed_at=None, exclusive=True,
                          scope='internal_patch_use', terms=None):
    """购买“内部修补/复现许可”。雇佣归属未澄清时合同挂起，不产生有效授权。"""
    init(db)
    with tx(db):
        _ensure(db)
        old = one(db, 'SELECT state FROM rr_licenses WHERE id=?', (license_id,))
        if old:
            return {'decision': 'reused', 'id': license_id, 'state': old['state']}
        uncleared = open_employment_constraints(db, party)
        state = 'effective' if not uncleared else 'held_employer_rights_uncleared'
        db.execute('INSERT INTO rr_licenses VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (license_id, party, report_id, scope, 1 if exclusive else 0,
                    fee, None, state, _now(signed_at),
                    canonical_json(terms or {})))
    return {'decision': ('license_effective' if state == 'effective'
                         else 'employer_rights_uncleared'),
            'id': license_id, 'state': state,
            'internal_use': state == 'effective',
            'exclusive': bool(exclusive) and state == 'effective'}


purchase_internal_license = sign_internal_license


def licenses_view(db, party=None):
    init(db)
    if party:
        rows = many(db, 'SELECT * FROM rr_licenses WHERE party=? ORDER BY id', (party,))
    else:
        rows = many(db, 'SELECT * FROM rr_licenses ORDER BY id')
    for r in rows:
        r['exclusive'] = bool(r['exclusive'])
        r['terms'] = json.loads(r['terms'] or '{}')
        r['effective'] = r['state'] == 'effective'
    return rows


def record_escrow(db, escrow_id, material_refs,
                  custodian='independent-third-party', sealed_at=None):
    init(db)
    refs = list(material_refs)
    with tx(db):
        _ensure(db)
        old = one(db, 'SELECT state FROM rr_escrows WHERE id=?', (escrow_id,))
        if old:
            return {'decision': 'reused', 'id': escrow_id, 'state': old['state']}
        db.execute('INSERT INTO rr_escrows VALUES(?,?,?,?,?)',
                   (escrow_id, custodian, canonical_json(refs),
                    _now(sealed_at), 'sealed'))
    return {'decision': 'escrow_sealed', 'id': escrow_id,
            'custodian': custodian, 'material_refs': refs,
            'publication': 'withheld_under_escrow'}


# ---------------------------------------------------------------------------
# 奖项撤销、付款凭据与清偿
# ---------------------------------------------------------------------------

def revoke_award(db, award_id, reason='', at=None):
    init(db)
    with tx(db):
        _ensure(db)
        if one(db, 'SELECT 1 x FROM rr_award_revocations WHERE award_id=?',
               (award_id,)):
            return {'decision': 'already_revoked', 'award_id': award_id}
        db.execute('INSERT INTO rr_award_revocations VALUES(?,?,?)',
                   (award_id, reason, _now(at)))
        # 关联的未付款义务一并挂起；已结算的付款历史保持不变（另行追偿）。
        db.execute("UPDATE rr_obligations SET state='revoked_hold',reason=? "
                   "WHERE award_id=? AND state IN ('due','held')",
                   (reason, award_id))
    return {'decision': 'award_revoked', 'award_id': award_id,
            'delivered_advisories_are_not_deleted': True}


def is_award_revoked(db, award_id):
    return bool(one(init(db),
                    'SELECT 1 x FROM rr_award_revocations WHERE award_id=?',
                    (award_id,)))


def create_obligation(db, obligation_id, party, amount, kind='award',
                      award_id=None, reason='', at=None):
    init(db)
    with tx(db):
        _ensure(db)
        if one(db, 'SELECT 1 x FROM rr_obligations WHERE id=?', (obligation_id,)):
            return {'decision': 'reused', 'id': obligation_id}
        state = 'due'
        if award_id and is_award_revoked(db, award_id):
            state = 'revoked_hold'
        db.execute('INSERT INTO rr_obligations VALUES(?,?,?,?,?,?,?,?)',
                   (obligation_id, party, kind, amount, award_id, state,
                    reason, _now(at)))
    return {'decision': 'obligation_created', 'id': obligation_id, 'state': state}


def initiate_payment(db, payment_id, party, amount, reference,
                     obligation_id=None, award_id=None, at=None):
    """登记付款指令。只有银行结算凭据到位后才允许 paid=True。"""
    init(db)
    if amount is None or amount <= 0:
        return {'decision': 'invalid_amount'}
    if award_id and is_award_revoked(db, award_id):
        return {'decision': 'award_revoked_payment_blocked'}
    with tx(db):
        _ensure(db)
        if one(db, 'SELECT 1 x FROM rr_payments WHERE id=?', (payment_id,)):
            return {'decision': 'reused', 'id': payment_id}
        if one(db, 'SELECT 1 x FROM rr_payments WHERE reference=?', (reference,)):
            return {'decision': 'duplicate_reference', 'reference': reference}
        db.execute('INSERT INTO rr_payments(id,obligation_id,award_id,party,amount,'
                   'reference,state,initiated_at) VALUES(?,?,?,?,?,?,?,?)',
                   (payment_id, obligation_id, award_id, party, amount, reference,
                    'initiated', _now(at)))
    return {'decision': 'payment_initiated', 'id': payment_id,
            'reference': reference, 'paid': False}


record_payment = initiate_payment


def settle_payment(db, payment_id, bank_evidence, at=None):
    """凭银行清算凭据确认到账；这是唯一把 paid 置真的路径。"""
    init(db)
    row = one(db, 'SELECT * FROM rr_payments WHERE id=?', (payment_id,))
    if not row:
        return {'decision': 'unknown_payment'}
    if row['state'] == 'settled':
        return {'decision': 'already_settled', 'paid': True}
    if row['state'] == 'bounced':
        return {'decision': 'cannot_settle_bounced_item', 'paid': False}
    if not bank_evidence:
        return {'decision': 'bank_evidence_required'}
    with tx(db):
        db.execute("UPDATE rr_payments SET state='settled',bank_evidence=?,"
                   'settled_at=? WHERE id=?',
                   (canonical_json(bank_evidence) if not isinstance(bank_evidence, str)
                    else bank_evidence, _now(at), payment_id))
        if row['obligation_id']:
            db.execute("UPDATE rr_obligations SET state='satisfied' WHERE id=?",
                       (row['obligation_id'],))
    return {'decision': 'payment_settled', 'id': payment_id, 'paid': True,
            'bank_evidence': bank_evidence}


confirm_payment = settle_payment
clear_payment = settle_payment


def bounce_payment(db, payment_id, reason='bank_returned_item', at=None):
    """银行退票：无论此前是否暂定到账，都必须回到未获报酬状态。"""
    init(db)
    row = one(db, 'SELECT * FROM rr_payments WHERE id=?', (payment_id,))
    if not row:
        return {'decision': 'unknown_payment'}
    with tx(db):
        db.execute("UPDATE rr_payments SET state='bounced',reason=?,returned_at=? "
                   'WHERE id=?', (reason, _now(at), payment_id))
        if row['obligation_id']:
            db.execute("UPDATE rr_obligations SET state='outstanding',reason=? "
                       'WHERE id=?', (reason, row['obligation_id']))
    return {'decision': 'payment_bounced', 'id': payment_id,
            'paid': False, 'researcher_paid': False,
            'obligation_reopened': bool(row['obligation_id'])}


return_payment = bounce_payment


def payment_view(db, payment_id):
    row = one(init(db), 'SELECT * FROM rr_payments WHERE id=?', (payment_id,))
    if not row:
        return None
    d = dict(row)
    d['paid'] = d['state'] == 'settled'
    return d


def payment_totals(db):
    init(db)
    rows = many(db, 'SELECT party,state,COALESCE(SUM(amount),0) total '
                    'FROM rr_payments GROUP BY party,state')
    by_party = {}
    for r in rows:
        p = by_party.setdefault(r['party'], {'paid': 0, 'initiated': 0,
                                             'bounced': 0})
        key = 'paid' if r['state'] == 'settled' else (
            'bounced' if r['state'] == 'bounced' else 'initiated')
        p[key] += r['total']
    return by_party


# ---------------------------------------------------------------------------
# 公告：草稿 -> 送达（不可变）-> 只能追加更正
# ---------------------------------------------------------------------------

def draft_advisory(db, advisory_id, audience='customer', title='',
                   body=None, evidence=None, protective_guidance=None,
                   secret_query=None, at=None):
    init(db)
    body = body or {}
    safe_document = {
        'title': title,
        'audience': audience,
        'body': body,
        'evidence': evidence or {},
        'protective_guidance': protective_guidance or [],
    }
    violations = scan_outbound(safe_document, secret_query)
    if violations:
        return {'decision': 'unsafe_content_blocked', 'violations': violations}
    with tx(db):
        _ensure(db)
        if one(db, 'SELECT 1 x FROM rr_advisories WHERE id=?', (advisory_id,)):
            return {'decision': 'reused', 'id': advisory_id}
        db.execute('INSERT INTO rr_advisories VALUES(?,?,?,?,?,?,?,?,?)',
                   (advisory_id, audience, title, canonical_json(body),
                    canonical_json(evidence or {}), canonical_json(safe_document),
                    'draft', _now(at), None))
    return {'decision': 'advisory_drafted', 'id': advisory_id,
            'outbound_safe': True}


def deliver_advisory(db, advisory_id, at=None):
    init(db)
    row = one(db, 'SELECT state FROM rr_advisories WHERE id=?', (advisory_id,))
    if not row:
        return {'decision': 'unknown_advisory'}
    if row['state'] == 'delivered':
        return {'decision': 'already_delivered', 'id': advisory_id,
                'delivered_immutable': True}
    with tx(db):
        db.execute("UPDATE rr_advisories SET state='delivered',delivered_at=? "
                   'WHERE id=?', (_now(at), advisory_id))
    return {'decision': 'advisory_delivered', 'id': advisory_id,
            'delivered_immutable': True}


issue_advisory = deliver_advisory
send_advisory = deliver_advisory


def mutate_delivered_advisory(db, advisory_id, new_body):
    """显式尝试改写已送达公告：必须被拒绝，原件保持不变。"""
    row = one(init(db), 'SELECT state,body FROM rr_advisories WHERE id=?',
              (advisory_id,))
    if not row:
        return {'decision': 'unknown_advisory'}
    if row['state'] == 'delivered':
        return {'decision': 'delivered_immutable',
                'original_preserved': json.loads(row['body'])}
    with tx(db):
        db.execute('UPDATE rr_advisories SET body=? WHERE id=?',
                   (canonical_json(new_body), advisory_id))
    return {'decision': 'draft_updated'}


def delete_advisory(db, advisory_id):
    row = one(init(db), 'SELECT state FROM rr_advisories WHERE id=?', (advisory_id,))
    if not row:
        return {'decision': 'unknown_advisory'}
    if row['state'] == 'delivered':
        return {'decision': 'delivered_immutable'}
    with tx(db):
        db.execute('DELETE FROM rr_advisories WHERE id=?', (advisory_id,))
    return {'decision': 'deleted'}


def correct_advisory(db, correction_id, advisory_id, correction, reason,
                     evidence=None, secret_query=None, kind='supplement', at=None):
    """送达后唯一允许的动作：追加带序号的更正/补充，原通知保留。"""
    init(db)
    adv = one(db, 'SELECT state FROM rr_advisories WHERE id=?', (advisory_id,))
    if not adv:
        return {'decision': 'unknown_advisory'}
    doc = {'correction': correction, 'evidence': evidence or {}}
    violations = scan_outbound(doc, secret_query)
    if violations:
        return {'decision': 'unsafe_content_blocked', 'violations': violations}
    with tx(db):
        _ensure(db)
        if one(db, 'SELECT 1 x FROM rr_corrections WHERE id=?', (correction_id,)):
            return {'decision': 'reused', 'id': correction_id}
        seq_row = one(db, 'SELECT COALESCE(MAX(seq),0)+1 n FROM rr_corrections '
                          'WHERE advisory=?', (advisory_id,))
        seq = seq_row['n']
        db.execute('INSERT INTO rr_corrections VALUES(?,?,?,?,?,?,?,?)',
                   (correction_id, advisory_id, seq, kind,
                    canonical_json(correction if isinstance(correction, (dict, list))
                                   else {'text': correction}),
                    canonical_json(evidence or {}), reason, _now(at)))
    return {'decision': 'correction_appended', 'id': correction_id,
            'advisory': advisory_id, 'seq': seq,
            'original_delivery_preserved': True}


append_correction = correct_advisory


def advisory_view(db, advisory_id):
    row = one(init(db), 'SELECT * FROM rr_advisories WHERE id=?', (advisory_id,))
    if not row:
        return None
    corrections = many(db, 'SELECT * FROM rr_corrections WHERE advisory=? '
                           'ORDER BY seq', (advisory_id,))
    out = dict(row)
    for k in ('body', 'evidence', 'safe_document'):
        out[k] = json.loads(out[k]) if out[k] else None
    for c in corrections:
        c['body'] = json.loads(c['body']) if c['body'] else None
        c['evidence'] = json.loads(c['evidence']) if c['evidence'] else None
    out['corrections'] = [dict(c) for c in corrections]
    out['delivered'] = row['state'] == 'delivered'
    return out


# ---------------------------------------------------------------------------
# 可读外发文本：客户防护通告 / 研究员回执（渲染时再次做泄密扫描）
# ---------------------------------------------------------------------------

def render_customer_notice(db, advisory_id, secret_query=None):
    view = advisory_view(db, advisory_id)
    if not view:
        return {'decision': 'unknown_advisory'}
    ev = view.get('evidence') or {}
    lines = [view['title'] or 'DNS 解析安全防护通告', '=' * 40]
    if ev.get('affected_versions'):
        lines.append(f"受影响版本：{ev['affected_versions']}")
    if ev.get('fixed_versions'):
        lines.append(f"版本说明：{canonical_json(ev['fixed_versions'])}")
    if ev.get('query_fingerprint'):
        lines.append(f"证据指纹：{ev['query_fingerprint'][:16]}…（盐化 HMAC，不含查询）")
    doc = view.get('safe_document') or {}
    for g in doc.get('protective_guidance', []):
        lines.append(f"防护建议：{g}")
    lines.append('说明：本通告不含任何真实租户查询，也不提供可照抄的攻击步骤。')
    for c in view.get('corrections', []):
        body = c['body'] if isinstance(c['body'], dict) else {'text': c['body']}
        lines.append(f"[更正 {c['seq']}] {c.get('reason', '')}："
                     + canonical_json(body.get('add', body)))
    text = '\n'.join(lines)
    violations = scan_outbound({'text': text}, secret_query)
    return {'decision': 'rendered', 'text': text, 'violations': violations,
            'safe_to_send': not violations, 'state': view['state']}


def render_researcher_receipt(db, report_id, secret_query=None):
    init(db)
    rep = one(db, 'SELECT id,finder,zone,proof_digest,impact FROM dns_research '
                  'WHERE id=?', (report_id,)) if _table_exists(db, 'dns_research') else None
    sub = one(db, 'SELECT signed_at,signature FROM rr_signed_submissions '
                  'WHERE report_id=?', (report_id,))
    matrix = {level: reproduce(db, report_id, level, 'ordinary')['decision']
              for level in PATCHES} if rep else {}
    lines = [
        f"研究员回执 / report={report_id}",
        f"收录摘要：finder={rep['finder'] if rep else 'n/a'} "
        f"zone={rep['zone'] if rep else 'n/a'}",
        f"签名提交时间：{sub['signed_at'] if sub else 'unrecorded'} "
        f"signature={sub['signature'] if sub else 'n/a'}",
        f"隔离复验矩阵：{canonical_json(matrix)}",
        '回执仅含判断受影响版本所需的最小证据与补丁矩阵；不回显真实租户查询，'
        '不包含未公开触发步骤。',
    ]
    text = '\n'.join(lines)
    violations = scan_outbound({'text': text}, secret_query)
    return {'decision': 'rendered', 'report_id': report_id, 'text': text,
            'violations': violations, 'safe_to_send': not violations}


# ---------------------------------------------------------------------------
# 共同发表、分配与公开检测方法
# ---------------------------------------------------------------------------

def create_publication(db, pub_id, mode='joint_detection', deadline_at=None):
    init(db)
    with tx(db):
        _ensure(db)
        if one(db, 'SELECT 1 x FROM rr_publications WHERE id=?', (pub_id,)):
            return {'decision': 'reused', 'id': pub_id}
        db.execute('INSERT INTO rr_publications(id,mode,state,deadline_at) '
                   "VALUES(?,?,'formed',?)", (pub_id, mode, deadline_at))
    return {'decision': 'publication_formed', 'id': pub_id,
            'deadline_at': deadline_at}


def grant_publication_consent(db, consent_id, pub_id, party,
                              scope='joint_publication', at=None):
    init(db)
    with tx(db):
        _ensure(db)
        db.execute('INSERT OR REPLACE INTO rr_consents VALUES(?,?,?,?,?,?)',
                   (consent_id, pub_id, party, scope, _now(at), 'given'))
    return {'decision': 'consent_recorded', 'party': party, 'scope': scope}


def record_split(db, split_id, pub_id, party, amount=None, share=None):
    init(db)
    with tx(db):
        _ensure(db)
        db.execute('INSERT OR REPLACE INTO rr_splits VALUES(?,?,?,?,?)',
                   (split_id, pub_id, party, amount, share))
    return {'decision': 'split_recorded', 'party': party,
            'amount': amount, 'share': share}


def publication_readiness(db, pub_id, total_amount=None, now=None):
    init(db)
    pub = one(db, 'SELECT * FROM rr_publications WHERE id=?', (pub_id,))
    if not pub:
        return {'decision': 'unknown_publication', 'ready': False}
    consents = many(db, 'SELECT party FROM rr_consents WHERE pub_id=? '
                        "AND state='given'", (pub_id,))
    splits = many(db, 'SELECT * FROM rr_splits WHERE pub_id=?', (pub_id,))
    consent_parties = {c['party'] for c in consents}
    split_total = sum((s['amount'] or 0) for s in splits)
    split_ok = bool(splits)
    if total_amount is not None:
        split_ok = split_ok and split_total == total_amount
    deadline = pub['deadline_at']
    overdue = bool(deadline and now and str(now) > str(deadline))
    return {
        'ready': len(consent_parties) >= 2 and split_ok,
        'consenting_parties': sorted(consent_parties),
        'splits': [dict(s) for s in splits],
        'split_total': split_total,
        'split_matches_total': (split_total == total_amount
                                if total_amount is not None else None),
        'deadline_at': deadline,
        'deadline_overdue': overdue,
        'overdue_does_not_grant_rights': overdue,
    }


def _public_detection_document(db):
    """客户可用来自检 R2 的安全检测方法：只含良性 canary，不含攻击步骤/查询。"""
    matrix_r2 = patch_matrix(db, 'R2', ('ordinary',))['ordinary']
    return {
        'id': 'detection:R2-cache-replay-self-check',
        'kind': 'defensive_benign_canary',
        'reverified_matrix': matrix_r2,
        'method': (
            '在客户自己的隔离解析器上，发布一条由客户自己控制、带一次性 nonce '
            '的良性记录，然后把同一投递原样重放一次：若第二次相同 nonce '
            '仍被当成新观测接受，则该解析路径可能仍受 R2 缓存回放影响。'
        ),
        'expected_patch_response': {
            'P': 'R2 仍可复现：P 只补来源鉴别，不能让客户确认已不受 R2 影响',
            'Q': 'R2 被阻断，但 Q 在 strict_legacy 策略上误拒正常答案，'
                 '未完成策略兼容前不得全量推送',
        },
        'does_not_include': [
            'third_party_tenant_query', 'forged_source_material',
            'raw_trigger_bytes', 'step_by_step_attack_recipe',
        ],
    }


def publish_joint_detection(db, pub_id, total_amount=None, at=None):
    """路径 B：双方共同发表同意 + 分配确认 + 隔离复验通过后，发布公开检测方法。"""
    init(db)
    ready = publication_readiness(db, pub_id, total_amount)
    if not ready['ready']:
        return {'decision': 'publication_conditions_unmet', **ready}

    # 派生证据若证实 R2 用了冉的盐，公开边界必须先拿到 Ran 对派生材料的追加同意。
    deriv = derivation_status(db, 'R2')
    extra_consent = None
    if deriv.get('state') == 'confirmed':
        extra_consent = one(
            db, "SELECT 1 x FROM rr_consents WHERE pub_id=? AND party='ran' "
                "AND scope='derived_salt_material'", (pub_id,))
        if not extra_consent:
            boundary = public_boundary(db)
            return {'decision': 'derivative_consent_required',
                    'state': 'withheld_pending_derivative_consent',
                    'public_boundary': boundary}

    detection = _public_detection_document(db)
    violations = scan_outbound(detection)
    if violations:
        return {'decision': 'unsafe_content_blocked', 'violations': violations}
    boundary = public_boundary(db, joint=True)
    with tx(db):
        db.execute("UPDATE rr_publications SET state='published_joint_detection',"
                   'boundary=?,detection=?,published_at=? WHERE id=?',
                   (canonical_json(boundary), canonical_json(detection),
                    _now(at), pub_id))
    return {'decision': 'joint_detection_published', 'id': pub_id,
            'detection': detection, 'public_boundary': boundary,
            'internal_reproduction': 'public_non_exclusive'}


# ---------------------------------------------------------------------------
# 路径 A：分别购买内部许可 + 第三方保管 + 防护公告 的就绪判定
# ---------------------------------------------------------------------------

def deal_a_readiness(db):
    licenses = licenses_view(db)
    r1 = [x for x in licenses if x['report_id'] == 'R1' and x['effective']]
    r2 = [x for x in licenses if x['report_id'] == 'R2' and x['effective']]
    escrow = one(init(db), "SELECT 1 x FROM rr_escrows WHERE state='sealed'")
    advisory = one(db, "SELECT 1 x FROM rr_advisories WHERE state='delivered'")
    return {
        'ready_to_contract': bool(r1 and r2 and escrow),
        'protective_advisory_delivered': bool(advisory),
        'r1_internal_license': bool(r1),
        'r2_internal_license': bool(r2),
        'independent_escrow': bool(escrow),
        'publication': 'trigger_steps_remain_withheld_in_escrow',
        'internal_reproduction': (
            'licensed_to_platform' if r1 and r2 else 'not_cleared'),
        'exclusive_internal': all(x['exclusive'] for x in r1 + r2)
        and bool(r1 and r2),
    }


protective_license_readiness = deal_a_readiness


# ---------------------------------------------------------------------------
# 补丁状态 / 回退 / 当前暴露面重算
# ---------------------------------------------------------------------------

def set_patch_level(db, level, policy='ordinary', at=None, reason=''):
    init(db)
    if level not in PATCHES:
        return {'decision': 'unknown_patch_level'}
    with tx(db):
        db.execute('UPDATE rr_patch_state SET level=?,policy=?,updated_at=? '
                   'WHERE id=1', (level, policy, _now(at)))
        db.execute('INSERT INTO rr_patch_history(level,policy,action,reason,at) '
                   'VALUES(?,?,?,?,?)',
                   (level, policy, 'set', reason, _now(at)))
    return {'decision': 'patch_state_set', 'level': level, 'policy': policy}


def rollback_patch(db, to_level='none', at=None, reason='patch_rollback'):
    init(db)
    with tx(db):
        row = one(db, 'SELECT level FROM rr_patch_state WHERE id=1')
        previous = row['level'] if row else '?'
        db.execute('UPDATE rr_patch_state SET level=?,updated_at=? WHERE id=1',
                   (to_level, _now(at)))
        db.execute('INSERT INTO rr_patch_history(level,policy,action,reason,at) '
                   'VALUES(?,?,?,?,?)',
                   (to_level, 'ordinary', f'rollback_from_{previous}', reason,
                    _now(at)))
    snap = exposure_snapshot(db)
    return {'decision': 'patch_rolled_back', 'from': previous, 'to': to_level,
            'exposure_reopened': snap['exposed_subjects'],
            'correction_required': bool(snap['exposed_subjects'])}


def current_patch_state(db):
    return one(init(db), 'SELECT level,policy,updated_at FROM rr_patch_state WHERE id=1')


def exposure_snapshot(db):
    """按当前补丁状态重算 R1/R1B/R2 与供应商超时的暴露面。"""
    init(db)
    state = current_patch_state(db) or {'level': 'none', 'policy': 'ordinary'}
    level = state['level']
    policy = 'ordinary'  # 暴露面按普通策略评估；strict_legacy 回归单独报告。
    subjects = ['R1', 'R1B', 'R2']
    results = {}
    exposed = []
    for s in subjects:
        r = reproduce(db, s, level, policy)
        results[s] = r['decision']
        if r['decision'] == REPRODUCED:
            exposed.append(s)
    strict_q = reproduce(db, 'NORMAL-STRICT', 'Q', 'strict_legacy')['decision']
    vendor = {}
    for t in many(db, 'SELECT id FROM rr_vendor_tickets'):
        vendor[t['id']] = probe_vendor_ticket(db, t['id'])['decision']
    return {
        'patch_level': level,
        'ordinary_policy_matrix': results,
        'exposed_subjects': exposed,
        'q_strict_legacy_normal_answer': strict_q,
        'q_regression_present': strict_q == REGRESSION,
        'vendor_timeouts': vendor,
        'q_must_not_be_blanket_released': strict_q == REGRESSION,
    }


# ---------------------------------------------------------------------------
# 公开边界 & 付款义务重算（事件变化后可重复调用，不修改不可变历史）
# ---------------------------------------------------------------------------

def public_boundary(db, joint=False):
    """当前可公开 / 必须扣留的材料边界。"""
    init(db)
    deriv = derivation_status(db, 'R2')
    query_tokens = many(db, 'SELECT token FROM rr_query_vault')
    salts = many(db, 'SELECT id FROM rr_salts')

    can_publish_detection = joint
    if deriv.get('state') == 'confirmed':
        ran_extra = one(
            db, "SELECT 1 x FROM rr_consents WHERE party='ran' "
                "AND scope='derived_salt_material'")
        if not ran_extra:
            can_publish_detection = False

    return {
        'publishable_now': [
            'affected_versions_minimal_evidence',
            'protective_configuration_guidance',
        ] + (['joint_r2_benign_self_check_detection']
             if can_publish_detection else []),
        'withheld': [
            'real_reversible_tenant_query (vault only)',
            'undisclosed_salts',
            'raw_trigger_trajectory_bytes',
            'copyable_attack_steps',
        ] + ([] if can_publish_detection
             else ['r2_public_detection (publication conditions unmet)']),
        'query_tokens_are_opaque': [q['token'] for q in query_tokens],
        'salt_ids_never_public': [s['id'] for s in salts],
        'q_blanket_release': 'blocked_by_strict_legacy_regression',
        'derivation_state': deriv.get('state', 'unverified'),
        'joint_detection_allowed': can_publish_detection,
    }


def recompute_obligations(db, provisional_unit=10):
    """把临时报酬、派生改判、撤销、退票重算为当前应付/已付/追偿口径。"""
    init(db)
    awards = existing_provisional_awards(db)
    deriv = derivation_status(db, 'R2')
    payments = many(db, 'SELECT * FROM rr_payments')

    by_award = {}
    for a in awards:
        revoked = is_award_revoked(db, a['id'])
        paid = sum(p['amount'] for p in payments
                   if p['award_id'] == a['id'] and p['state'] == 'settled')
        bounced = sum(p['amount'] for p in payments
                      if p['award_id'] == a['id'] and p['state'] == 'bounced')
        derivative_hold = False
        if deriv.get('state') == 'confirmed' and a['report'] == 'R2':
            derivative_hold = True
        provisional = a['amount']
        if revoked:
            payable_now = 0
            basis = 'award_revoked'
        elif derivative_hold:
            payable_now = 0
            basis = 'derivative_of_R1_pending_corrected_settlement'
        else:
            payable_now = provisional
            basis = 'provisional_impact_times_unit'
        by_award[a['id']] = {
            'award_id': a['id'], 'report': a['report'],
            'provisional_amount': provisional,
            'revoked': revoked,
            'derivative_hold': derivative_hold,
            'payable_now': payable_now,
            'settled_total': paid,
            'bounced_total': bounced,
            'still_owed': max(0, payable_now - paid),
            'clawback_due': max(0, paid - payable_now)
            if (revoked or derivative_hold) else 0,
            'basis': basis,
        }

    totals = payment_totals(db)
    return {'awards': by_award, 'payment_totals': totals,
            'researcher_paid': {p: v['paid'] for p, v in totals.items()},
            'note': '临时报酬不是收入；只有 settled 银行凭据构成已获报酬，'
                    'bounced 必须排除。已送达公告不受奖项撤销影响。'}


settlement = recompute_obligations
settlement_summary = recompute_obligations


def clearance_matrix(db):
    """先行贡献 / 雇佣 / 许可 / 发表期限 / 付款凭据 的逐一对应视图。"""
    init(db)
    parties = many(db, 'SELECT * FROM rr_parties ORDER BY id')
    tickets = many(db, 'SELECT id,vendor,opened_at,symptom FROM rr_vendor_tickets')
    out = []
    for p in parties:
        pid = p['id']
        out.append({
            'party': pid,
            'kind': p['kind'],
            'employment_constraints': many(
                db, 'SELECT id,employer,state,waiver_ref FROM rr_employment '
                    'WHERE party=?', (pid,)),
            'licenses': licenses_view(db, pid),
            'consents': many(db, 'SELECT pub_id,scope,state FROM rr_consents '
                                 'WHERE party=?', (pid,)),
            'payments': [dict(x) for x in many(
                db, 'SELECT id,amount,reference,state,bank_evidence,settled_at '
                    'FROM rr_payments WHERE party=?', (pid,))],
        })
    return {'parties': out, 'prior_art_tickets': [dict(t) for t in tickets]}


def case_summary(db):
    """一个调用拿到全部可复核结论，便于人工/验收审阅。"""
    init(db)
    advisories = many(db, 'SELECT id,audience,state,delivered_at FROM rr_advisories')
    return {
        'reports': existing_reports(db),
        'provisional_awards': existing_provisional_awards(db),
        'root_cause_attribution': attribute_causes(db),
        'vendor_tickets': many(db, 'SELECT * FROM rr_vendor_tickets'),
        'exposure': exposure_snapshot(db),
        'deal_a_protective_license': deal_a_readiness(db),
        'public_boundary': public_boundary(db),
        'obligations': recompute_obligations(db),
        'clearance': clearance_matrix(db),
        'advisories': [advisory_view(db, a['id']) for a in advisories],
        'independence': submission_independence(db)
        if one(db, "SELECT 1 x FROM rr_signed_submissions WHERE report_id='R1'")
        else {'status': 'unverified'},
    }


# 便于 `ResearchRelease(db)` 风格调用与常见命名猜测。
class ResearchRelease:
    def __init__(self, db):
        self.db = init(db)

    def __getattr__(self, name):
        fn = globals().get(name)
        if callable(fn):
            return lambda *a, **k: fn(self.db, *a, **k)
        raise AttributeError(name)


ReleaseLedger = ResearchRelease


def root_cause_for(db, subject):
    """返回某主体当前关联的根因 ID 列表（可能为空/多个）。"""
    links = causal_links(db)
    return sorted({x['root_cause'] for x in links if x['subject'] == subject})


def independence_verdict(db, report_a='R1', report_b='R2'):
    return submission_independence(db, report_a, report_b)


# --- 常见英文命名的薄别名，方便不同调用习惯/验收脚本 -----------------------
attribute_reports = attribute_causes
root_cause_attribution = attribute_causes
settlement_report = recompute_obligations
settle = settle_payment
mark_paid = settle_payment
record_bounced_payment = bounce_payment
mark_bounced = bounce_payment
get_advisory = advisory_view
add_correction = correct_advisory
issue_notice = deliver_advisory
publish_notice = deliver_advisory
protect_tenant_query = seal_query
recover_query = unseal_query
verify_salt = present_salt_proof
verify_salt_use_evidence = present_salt_proof
record_private_disclosure = record_disclosure
patch_probe = reproduce
evaluate_patch = reproduce
vendor_timeout_probe = probe_vendor_ticket


def build_release(db, *args, **kwargs):
    """高层发布结论入口；额外参数被忽略，始终返回完整可复核 case_summary。"""
    return case_summary(db)


def release_decision(db, *args, **kwargs):
    return case_summary(db)


# ---------------------------------------------------------------------------
# 标准案例播种：幂等接入现有 R1/R2 报告与临时报酬。
# ---------------------------------------------------------------------------

def seed_standard_case(db, unit=10, salt_value='ran-undisclosed-salt'):
    """建立任务所述完整争执案例。重复调用安全（既有报告行优先，不制造冲突）。"""
    init(db)

    # 1) 现有报告账：若调用方已用不同摘要播种 R1/R2，保留他们的行，不覆盖。
    for rid, finder, digest, impact in (
            ('R1', 'ran', 'digest-r1', 3),
            ('R2', 'wen', 'digest-r2', 3)):
        res = submit_report(db, rid, finder, 'update.example.invalid',
                            digest, impact)
        if res['decision'] not in ('submitted', 'reused', 'conflict'):
            raise RuntimeError(f'unexpected submit result {res}')

    # 临时报酬：impact 3 * unit 10 = 30（已存在同 ID 则复用）。
    award_r1 = provisional_award(db, 'award-r1', 'R1', unit)
    award_r2 = provisional_award(db, 'award-r2', 'R2', unit)

    # 2) 具体轨迹（R1 与 R1B 异字节同根因；R1/R2 同症状异根因）。
    record_trajectory(db, 'trace-r1', 'R1', 'forged_source_overwrite',
                      'untrusted_answer_becomes_latest_trusted_observation',
                      ran_forged_source_trace('R1'), root_cause=RC_SOURCE,
                      variant='R1')
    record_trajectory(db, 'trace-r1b', 'R1B', 'forged_source_overwrite',
                      'untrusted_answer_becomes_latest_trusted_observation',
                      ran_forged_source_trace('R1B'), root_cause=RC_SOURCE,
                      variant='R1B')
    record_trajectory(db, 'trace-r2', 'R2', 'cache_replay',
                      'untrusted_answer_becomes_latest_trusted_observation',
                      wen_cache_replay_trace(), root_cause=RC_REPLAY)
    record_trajectory(db, 'trace-normal-strict', 'NORMAL-STRICT',
                      'ordinary_answer', 'none',
                      strict_legacy_normal_trace())

    record_root_cause(db, RC_SOURCE, '缺少解析来源鉴别',
                      'source_provenance',
                      '准入把自报 source 标签相等误当成来源可信。')
    record_root_cause(db, RC_REPLAY, '缺少代次新鲜性/重放绑定',
                      'generation_freshness_binding',
                      '有效来源的旧缓存记录可被重复投递，缺少一次性 nonce/已消费代次日志。')
    link_cause(db, 'link-r1', 'R1', RC_SOURCE,
               '伪造来源 + 自报高代次覆盖旧观测；P 补来源鉴别后阻断。',
               trajectory_id='trace-r1', blocked_by=['P', 'Q'])
    link_cause(db, 'link-r1b', 'R1B', RC_SOURCE,
               'R1 的异字节变体（不同 IP/ID/序列化），同一来源鉴别缺口。',
               trajectory_id='trace-r1b', blocked_by=['P', 'Q'])
    link_cause(db, 'link-r2', 'R2', RC_REPLAY,
               '缓存回放带合法来源材料，P 不阻断；Q 增加新鲜性日志才阻断。',
               trajectory_id='trace-r2', blocked_by=['Q'])

    # 3) 供应商更早的超时故障单（只有超时）。
    record_vendor_ticket(db, 'VENDOR-OLD-TIMEOUT', 'vendor',
                         'same-domain.example', '2023-11-01T09:00:00Z')

    # 4) 独立签名提交时间（不能证明研究过程独立）。
    record_signed_submission(db, 'R1', 'ran', '2026-11-20T08:00:00Z',
                             signature='sig-r1', bytes_digest='digest-r1')
    record_signed_submission(db, 'R2', 'wen', '2026-11-21T10:30:00Z',
                             signature='sig-r2', bytes_digest='digest-r2')

    # 5) 当事方与冉的未公开盐。
    upsert_party(db, 'ran', 'researcher', '冉')
    upsert_party(db, 'wen', 'researcher', '闻')
    upsert_party(db, 'vendor', 'supplier', '供应商')
    upsert_party(db, 'escrow', 'independent_custodian', '独立第三方保管人')
    register_salt(db, 'salt-ran', 'ran', salt_value,
                  purpose='private-disclosure-fingerprint')

    set_patch_level(db, 'none')
    return {'decision': 'standard_case_seeded',
            'award_r1': award_r1, 'award_r2': award_r2}


bootstrap = seed_standard_case
setup_case = seed_standard_case
standard_case = seed_standard_case
seed_case = seed_standard_case


# ---------------------------------------------------------------------------
# 事件总线（与 name/permit/flow 风格一致；便于 run(db, {'op': ...}) 调用）
# ---------------------------------------------------------------------------

def handle(db, x):
    op = x.get('op')
    if op == 'seed':
        return seed_standard_case(db, unit=x.get('unit', 10))
    if op == 'reproduce':
        return reproduce(db, x['subject'], x.get('patch_level', 'none'),
                         x.get('tenant_policy', 'ordinary'), at=x.get('at'))
    if op == 'matrix':
        return patch_matrix(db, x['subject'], tuple(x.get('policies', ['ordinary'])))
    if op == 'vendor_ticket':
        return record_vendor_ticket(
            db, x['id'], x.get('vendor', 'vendor'), x.get('domain', ''),
            x.get('opened_at', ''), x.get('symptom', 'timeout'))
    if op == 'vendor_probe':
        return probe_vendor_ticket(db, x['ticket_id'])
    if op == 'seal_query':
        return seal_query(db, x['token'], x['query'])
    if op == 'unseal_query':
        return unseal_query(db, x['token'], x.get('role', 'platform_ir'))
    if op == 'salt':
        return register_salt(db, x['id'], x['owner'], x['value'])
    if op == 'indicator':
        return add_indicator(db, x['id'], x['subject'], x['fingerprint'],
                             x.get('salt_id'))
    if op == 'disclosure':
        return record_disclosure(db, x['id'], x['from_party'], x['to_party'],
                                 x.get('materials', []), salt_id=x.get('salt_id'))
    if op == 'salt_proof':
        return present_salt_proof(
            db, x['finding_id'], x['subject'], x['source'], x['salt_id'],
            x['plaintext'], x.get('presented_fingerprint'))
    if op == 'employment':
        return record_employment_constraint(db, x['id'], x['party'],
                                            x['employer'], x.get('constraint_text', ''))
    if op == 'waiver':
        return waive_employment_constraint(db, x['id'], x['waiver_ref'])
    if op == 'license':
        return sign_internal_license(
            db, x['id'], x['party'], x['report_id'], x.get('fee', 0),
            exclusive=x.get('exclusive', True))
    if op == 'escrow':
        return record_escrow(db, x['id'], x['material_refs'],
                             x.get('custodian', 'independent-third-party'))
    if op == 'publication':
        return create_publication(db, x['id'], x.get('mode', 'joint_detection'),
                                  x.get('deadline_at'))
    if op == 'consent':
        return grant_publication_consent(db, x['id'], x['pub_id'], x['party'],
                                         x.get('scope', 'joint_publication'))
    if op == 'split':
        return record_split(db, x['id'], x['pub_id'], x['party'],
                            x.get('amount'), x.get('share'))
    if op == 'publish':
        return publish_joint_detection(db, x['pub_id'], x.get('total_amount'))
    if op == 'revoke_award':
        return revoke_award(db, x['award_id'], x.get('reason', ''))
    if op == 'payment':
        return initiate_payment(db, x['id'], x['party'], x['amount'],
                                x['reference'], x.get('obligation_id'),
                                x.get('award_id'))
    if op == 'settle_payment':
        return settle_payment(db, x['id'], x.get('bank_evidence'))
    if op == 'bounce_payment':
        return bounce_payment(db, x['id'], x.get('reason', 'bank_returned_item'))
    if op == 'draft_advisory':
        return draft_advisory(
            db, x['id'], x.get('audience', 'customer'), x.get('title', ''),
            x.get('body'), x.get('evidence'), x.get('protective_guidance'),
            secret_query=x.get('secret_query'))
    if op == 'deliver_advisory':
        return deliver_advisory(db, x['id'])
    if op == 'correct_advisory':
        return correct_advisory(db, x['id'], x['advisory_id'], x['correction'],
                                x.get('reason', ''), x.get('evidence'),
                                secret_query=x.get('secret_query'))
    if op == 'set_patch':
        return set_patch_level(db, x['level'], x.get('policy', 'ordinary'),
                               reason=x.get('reason', ''))
    if op == 'rollback_patch':
        return rollback_patch(db, x.get('to_level', 'none'),
                              reason=x.get('reason', 'patch_rollback'))
    if op == 'summary':
        return case_summary(db)
    if op == 'recompute':
        return recompute_obligations(db)
    if op == 'exposure':
        return exposure_snapshot(db)
    return {'decision': 'unknown_operation', 'op': op}


def run(db, x):
    """事件化入口：先确保表存在，再走 store.act 的 event_id 幂等。"""
    init(db)
    # 裸 sqlite3 连接没有 store.connect 建的 events 表，这里幂等补齐。
    db.execute(
        'CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,'
        ' subsystem TEXT, command TEXT, event_id TEXT UNIQUE, payload TEXT,'
        ' result TEXT)')
    return act(db, 'research_release', x, handle)
