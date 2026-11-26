"""Isolated resolver behavior probe for two reported triggers."""

from .store import one


def evaluate(db, report_id, patch_level, tenant_policy):
    report = one(db, 'SELECT id,zone FROM dns_research WHERE id=?', (report_id,))
    if not report:
        return 'unknown_report'
    if patch_level == 'Q' and tenant_policy == 'strict_legacy':
        return 'normal_answer_rejected'
    if report_id == 'R1' and patch_level in ('P', 'Q'):
        return 'attack_blocked'
    if report_id == 'R2' and patch_level == 'Q':
        return 'attack_blocked'
    return 'attack_reproduced'
