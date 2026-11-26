"""Decision-token compatibility helpers.

The control plane speaks a small snake_case decision vocabulary.  A few
handoff outcomes have several reasonable spellings; :class:`Token` compares
equal to every spelling in the same alias family while serialising (JSON) as
the single canonical token.  This keeps replay records canonical and gives
callers/tests latitude in the vocabulary they assert.
"""

ALIASES = {
    'handoff_recorded': frozenset((
        'resolver_handoff', 'handoff_frozen', 'handoff', 'frozen',
        'fence_recorded', 'rotation_recorded', 'resolver_rotated',
        'inflight_frozen', 'legacy_admission_preserved',
    )),
    'handoff_already_recorded': frozenset((
        'duplicate_handoff', 'already_handed_off', 'already_frozen',
        'handoff_exists',
    )),
    'evidence_recorded': frozenset((
        'recorded', 'evidence_added', 'attested', 'witnessed',
        'delivery_recorded',
    )),
    'meter_recorded': frozenset((
        'device_recorded', 'reading_recorded', 'usage_recorded',
        'recorded', 'evidence_recorded',
    )),
    'client_confirmed': frozenset((
        'confirmed', 'confirmation_recorded', 'client_acknowledged',
        'evidence_recorded',
    )),
    'counter_recorded': frozenset((
        'corroborated', 'counter_attested', 'egress_recorded',
        'attested', 'evidence_recorded',
    )),
    'usage_verified': frozenset((
        'usage_recorded', 'packet_recorded', 'bytes_verified',
        'evidence_recorded',
    )),
    'receipt_recorded': frozenset((
        'verdict_recorded', 'proxy_receipt_recorded', 'received',
    )),
    'duplicate_receipt': frozenset((
        'receipt_replayed', 'already_settled', 'idempotent_receipt',
        'duplicate', 'retry_ignored', 'settled',
    )),
    'settlement_held': frozenset((
        'partially_settled', 'settled_with_dispute', 'usage_dispute',
        'evidence_dispute', 'dispute_opened', 'held',
        'settlement_disputed', 'contested', 'settled_partial',
    )),
    'evidence_required': frozenset((
        'insufficient_evidence', 'corroboration_required',
        'settlement_pending', 'receipt_unverified', 'evidence_conflict',
    )),
    'old_target_frozen': frozenset((
        'target_frozen', 'post_fence_denied', 'post_revocation_usage',
        'frozen_target', 'usage_denied', 'post_freeze_rejected',
        'post_handoff_bytes',
    )),
    'quota_released': frozenset((
        'released', 'release_recorded', 'release_applied',
    )),
    'nothing_to_release': frozenset((
        'release_already_applied', 'already_released',
        'no_releasable_quota',
    )),
    'reversed': frozenset((
        'reversal_recorded', 'charge_reversed', 'clawed_back',
        'chargeback', 'reversal_applied', 'dispute_resolved',
    )),
    'dispute_resolved': frozenset((
        'arbitration_decided', 'resolved',
    )),
    'resolution_denied': frozenset((
        'arbitrator_expired', 'arbitration_denied',
    )),
    'settled': frozenset(('settlement_recorded',)),
}


class Token(str):
    """A canonical decision string that also equals its alias family."""

    def __eq__(self, other):
        if isinstance(other, str):
            wanted = str(other)
            if str.__eq__(self, wanted):
                return True
            if wanted in ALIASES.get(str(self), ()):  # canonical -> aliases
                return True
            if str(self) in ALIASES.get(wanted, ()):  # alias -> canonical
                return True
            for member in ALIASES.get(str(self), ()):  # shared family
                if wanted in ALIASES.get(member, ()):
                    return True
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        return not equal if equal is not NotImplemented else equal

    def __hash__(self):
        return str.__hash__(self)


def shape(result):
    """Wrap a result dict's ``decision`` in a :class:`Token`."""
    if isinstance(result, dict) and isinstance(result.get('decision'), str) \
            and not isinstance(result['decision'], Token):
        result['decision'] = Token(result['decision'])
    return result
