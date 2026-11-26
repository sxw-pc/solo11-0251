"""RF interference resolution for the resolver site.

This module replaces single-reading, single-device attribution with an
evidence chain:

* survey samples are configuration-, point-, calibration- and load-bound;
* a provisional release is blocked by any high-load exceedance in the same
  measured configuration (see :mod:`cloudcourt.rf_clearance`);
* a controlled 2x2 trial set is *diagnosed*, never reduced to a single label;
* each engineering action fences the evidence of the configuration it changed;
* delivery requires a passing local joint-spike retest, the neighbour's
  acceptance at its own receive position, the customer's contracted capacity
  and uplink, and a regulator submission pointing at the same measured
  configuration;
* a rollback (filter removed, old PSU re-enabled) or a regulator withdrawal
  invalidates the old release instead of leaving it in force.

The only claims made are the ones the recorded evidence supports.  In
particular there is no "average field" report and no "last device on" cause.
"""

import json

from . import rf_clearance, rf_survey, rf_trial
from .store import act, many, one

ROLLBACK_KINDS = ('revert_psu', 'remove_filter')
ACTION_BRANCH = {
    'psu_filter': 'in_place',
    'bridge_ground': 'in_place',
    'carrier_power_adjust': 'in_place',
    'load_adjust': 'in_place',
    'relocate_carrier_antenna': 'separation',
    'migrate_resolution': 'separation',
}
BRANCH_REQUIRED = {
    'in_place': ('psu_filter', 'bridge_ground'),
    'separation': ('relocate_carrier_antenna', 'migrate_resolution'),
}
BRANCH_DIFFERENCES = {
    'in_place': {
        'measurement_point': 'neighbour original receive position',
        'responsibility': 'resolver site (filter/ground) + operator (antenna power)',
        'customer_latency': 'unchanged local processing',
        'regulator_point': 'neighbour original receive position',
        'service_window': 'both parties stay local during joint spike retest',
    },
    'separation': {
        'measurement_point': 'neighbour original receive position',
        'responsibility': 'operator licensed rooftop + resolver remote cabinet',
        'customer_latency': 'remote cabinet latency must stay within contract',
        'regulator_point': 'neighbour original receive position',
        'service_window': 'customer service moves; operator maintenance location differs',
    },
}

SCHEMA = rf_survey.SCHEMA + rf_trial.SCHEMA + rf_clearance.SCHEMA + '''
CREATE TABLE IF NOT EXISTS rf_sites(
    site TEXT PRIMARY KEY, neighbor_site TEXT,
    neighbor_capacity_mbps REAL, customer_capacity_mbps REAL,
    customer_latency_ms REAL, state TEXT
);
CREATE TABLE IF NOT EXISTS rf_receivers(
    id TEXT PRIMARY KEY, site TEXT, position TEXT, config TEXT,
    required_errors INTEGER, state TEXT, at INTEGER
);
CREATE TABLE IF NOT EXISTS rf_permits(
    id TEXT PRIMARY KEY, site TEXT, position TEXT, issuer TEXT,
    at INTEGER, state TEXT
);
CREATE TABLE IF NOT EXISTS rf_experiments(
    id TEXT PRIMARY KEY, site TEXT, config TEXT, receiver TEXT,
    load_pct INTEGER, baseline INTEGER, tolerance INTEGER, at INTEGER,
    verdict TEXT, candidates TEXT, ruled_out TEXT, deltas TEXT,
    single_action TEXT, blockers TEXT
);
CREATE TABLE IF NOT EXISTS rf_spectrum(
    id TEXT PRIMARY KEY, site TEXT, config TEXT, frequency_khz INTEGER,
    peak_mv INTEGER, tracks TEXT, at INTEGER, attribution TEXT
);
CREATE TABLE IF NOT EXISTS rf_actions(
    id TEXT PRIMARY KEY, site TEXT, branch TEXT, kind TEXT,
    config_before TEXT, config_after TEXT, at INTEGER,
    permit TEXT, cabinet TEXT, position TEXT, uplink TEXT,
    detail TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS rf_retests(
    id TEXT PRIMARY KEY, action TEXT, site TEXT, branch TEXT,
    config TEXT, mode TEXT, receiver TEXT, position TEXT,
    psu_on INTEGER, carrier_on INTEGER, errors INTEGER, baseline INTEGER,
    instrument TEXT, calibrated_until INTEGER, local_neighbor INTEGER,
    local_customer INTEGER, at INTEGER, state TEXT
);
CREATE TABLE IF NOT EXISTS rf_receipts(
    id TEXT PRIMARY KEY, action TEXT, site TEXT, party TEXT,
    retest TEXT, config TEXT, position TEXT, at INTEGER,
    signer TEXT, state TEXT, capacity_mbps REAL, latency_ms REAL,
    uplink TEXT, note TEXT
);
CREATE TABLE IF NOT EXISTS rf_submissions(
    id TEXT PRIMARY KEY, action TEXT, site TEXT, config TEXT,
    position TEXT, at INTEGER, body TEXT, state TEXT
);
'''


def _dumps(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _loads(value):
    return json.loads(value) if value else None


def _latest_receiver(db, site):
    return one(db, '''SELECT * FROM rf_receivers WHERE site=?
                      ORDER BY at DESC, rowid DESC LIMIT 1''', (site,))


def _branch_actions(db, site, branch):
    return many(db, '''SELECT * FROM rf_actions
                       WHERE site=? AND branch=? AND state='committed'
                       ORDER BY at, rowid''', (site, branch))


def _latest_action(db, site, branch):
    rows = _branch_actions(db, site, branch)
    return rows[-1] if rows else None


def _last_rollback(db, site, branch):
    return one(db, '''SELECT * FROM rf_actions
                      WHERE site=? AND branch=? AND kind IN (?,?)
                      ORDER BY at DESC, rowid DESC LIMIT 1''',
               (site, branch, *ROLLBACK_KINDS))


def _valid_retest(db, action_id, config, after=None):
    return one(db, '''SELECT * FROM rf_retests
                      WHERE action=? AND config=? AND state='passed'
                        AND mode='local_joint_spike' AND at>=?
                      ORDER BY at DESC, rowid DESC LIMIT 1''',
               (action_id, config, -1 if after is None else after))


def _receipt(db, action_id, party):
    return one(db, '''SELECT * FROM rf_receipts
                      WHERE action=? AND party=? AND state='accepted'
                      ORDER BY at DESC, rowid DESC LIMIT 1''',
               (action_id, party))


def _submission(db, action_id, config, position):
    return one(db, '''SELECT * FROM rf_submissions
                      WHERE action=? AND config=? AND position=?
                        AND state='filed'
                      ORDER BY at DESC, rowid DESC LIMIT 1''',
               (action_id, config, position))


def _diagnose(db, x):
    """Classify the controlled trial set without choosing a single source."""
    experiment = x['experiment']
    site = x['site']
    rows = many(db, '''SELECT * FROM rf_trials WHERE experiment=? AND site=?
                       ORDER BY at, rowid''', (experiment, site))
    combos = {}
    for row in rows:
        combos.setdefault((row['psu_on'], row['carrier_on']), []).append(row)
    needed = [(0, 0), (1, 0), (0, 1), (1, 1)]
    missing = [f'psu_on={a},carrier_on={b}' for a, b in needed
               if (a, b) not in combos]
    if missing:
        return {'decision': 'experiment_incomplete', 'missing': missing}

    tolerance = int(x.get('tolerance', 20))
    if tolerance < 0:
        return {'decision': 'invalid_tolerance'}
    config = x.get('config')
    if any(row['config'] != config for row in rows):
        return {'decision': 'trial_configuration_mismatch',
                'expected': config}
    if any(row['load_pct'] != x.get('load_pct') for row in rows):
        return {'decision': 'trial_load_mismatch',
                'expected': x.get('load_pct')}
    if any(row['receiver'] != x.get('receiver') for row in rows):
        return {'decision': 'trial_receiver_mismatch',
                'expected': x.get('receiver')}
    receiver = one(db, 'SELECT * FROM rf_receivers WHERE id=?',
                   (x['receiver'],))
    if not receiver:
        return {'decision': 'unknown_receiver'}
    if receiver['site'] != site:
        return {'decision': 'receiver_site_mismatch'}

    repeatability = {}
    unstable = []
    for combo in needed:
        values = [row['neighbor_errors'] for row in combos[combo]]
        spread = max(values) - min(values)
        repeatability[f'{combo[0]},{combo[1]}'] = {
            'runs': len(values), 'min': min(values), 'max': max(values),
            'spread': spread,
        }
        if spread > tolerance:
            unstable.append(f'{combo[0]},{combo[1]}')

    baseline = max(row['baseline'] for row in rows)
    both_off = max(row['neighbor_errors'] for row in combos[(0, 0)])
    psu_residual = max(row['neighbor_errors'] for row in combos[(1, 0)])
    carrier_residual = max(row['neighbor_errors'] for row in combos[(0, 1)])
    both_low = min(row['neighbor_errors'] for row in combos[(1, 1)])
    both_high = max(row['neighbor_errors'] for row in combos[(1, 1)])

    d_psu = psu_residual - both_off
    d_carrier = carrier_residual - both_off
    d_both_low = both_low - both_off
    d_both_high = both_high - both_off
    additive = d_psu + d_carrier

    candidates = []
    ruled_out = []
    verdict = 'not_attributable_to_single_source'
    required = ['post_action_joint_spike_retest']
    blockers = []
    if unstable:
        blockers.append('repeatability_exceeded')
    if both_off > baseline + tolerance:
        blockers.append('background_above_baseline')
        candidates.append('neighbor_receiver_impaired')

    psu_effect = d_psu > tolerance
    carrier_effect = d_carrier > tolerance
    joint_effect = d_both_low > tolerance

    background_high = both_off > baseline + tolerance
    if not psu_effect and not carrier_effect:
        if background_high:
            verdict = 'receiver_impaired_before_intervention'
            required.append('receiver_intermod_test')
        elif joint_effect:
            verdict = 'joint_only_effect'
            candidates.extend(['neighbor_receiver_intermod',
                               'joint_common_path_coupling'])
            required.append('receiver_intermod_test')
        elif not unstable:
            verdict = 'no_measurable_effect'
    else:
        if psu_effect and carrier_effect:
            candidates.extend(['two_independent_leaks',
                               'shared_ground_nonlinear_coupling'])
            if additive > d_both_high + tolerance:
                verdict = 'sub_additive_receiver_compression'
                candidates.append('neighbor_receiver_compression')
            elif additive < d_both_low - tolerance:
                verdict = 'super_additive_common_path'
                candidates.insert(0, 'shared_ground_nonlinear_coupling')
            elif not unstable:
                verdict = 'multiple_contributors'
            required.append('separation_or_ground_bond_retest')
        elif psu_effect:
            candidates.append('psu_leak')
            verdict = 'psu_contributor_supported_confirmation_required'
            ruled_out.append({
                'candidate': 'carrier_only_attribution',
                'reason': 'removing the carrier leaves errors above tolerance',
            })
        else:
            candidates.append('carrier_leak')
            verdict = 'carrier_contributor_supported_confirmation_required'
            ruled_out.append({
                'candidate': 'psu_only_attribution',
                'reason': 'removing the PSU leaves errors above tolerance',
            })
        if psu_effect and carrier_effect:
            ruled_out.append({
                'candidate': 'neighbor_receiver_intermod_as_sole_cause',
                'reason': 'each device alone raises neighbour errors, so the '
                          'failure is not produced only when both are present',
            })

    acceptance = receiver['required_errors']
    single_action = {
        # Only the PSU running = the carrier has been switched off.
        'carrier_removed_residual': psu_residual,
        # Only the carrier running = the PSU has been switched off.
        'psu_removed_residual': carrier_residual,
        'receiver_acceptance': acceptance,
        'psu_removal_alone_insufficient': carrier_residual > acceptance,
        'carrier_removal_alone_insufficient': psu_residual > acceptance,
    }
    if single_action['psu_removal_alone_insufficient']:
        blockers.append('psu_removal_alone_insufficient')
    if single_action['carrier_removal_alone_insufficient']:
        blockers.append('carrier_removal_alone_insufficient')

    deltas = {
        'both_off': both_off,
        'psu_only': psu_residual,
        'carrier_only': carrier_residual,
        'both_on_range': [both_low, both_high],
        'psu_contribution': d_psu,
        'carrier_contribution': d_carrier,
        'both_contribution_range': [d_both_low, d_both_high],
        'additive_sum': additive,
    }
    return {
        'decision': 'diagnosed', 'site': site, 'config': x.get('config'),
        'receiver': receiver['id'], 'verdict': verdict,
        'attribution': 'not_attributable_to_single_source',
        'candidates': candidates, 'ruled_out': ruled_out,
        'deltas': deltas, 'repeatability': repeatability,
        'single_action': single_action,
        'required_discriminators': required, 'blockers': blockers,
        'load_pct': x.get('load_pct'), 'baseline': baseline,
        'tolerance': tolerance,
    }


def _record_diagnosis(db, x, result):
    db.execute('''INSERT INTO rf_experiments
                  (id,site,config,receiver,load_pct,baseline,tolerance,at,
                   verdict,candidates,ruled_out,deltas,single_action,blockers)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                  ON CONFLICT(id) DO UPDATE SET
                    site=excluded.site, config=excluded.config,
                    receiver=excluded.receiver, load_pct=excluded.load_pct,
                    baseline=excluded.baseline, tolerance=excluded.tolerance,
                    at=excluded.at, verdict=excluded.verdict,
                    candidates=excluded.candidates, ruled_out=excluded.ruled_out,
                    deltas=excluded.deltas, single_action=excluded.single_action,
                    blockers=excluded.blockers''',
               (x['experiment'], x['site'], x.get('config'), x.get('receiver'),
                x.get('load_pct'), result.get('baseline'), result.get('tolerance'),
                x.get('at'), result.get('verdict'),
                _dumps(result.get('candidates', [])),
                _dumps(result.get('ruled_out', [])),
                _dumps(result.get('deltas', {})),
                _dumps(result.get('single_action', {})),
                _dumps(result.get('blockers', []))))


def _withdraw_config_clearances(db, site, config, reason):
    rf_clearance.ensure(db)
    rows = many(db, 'SELECT id FROM rf_clearances WHERE site=? AND config IS ?',
                (site, config))
    for row in rows:
        db.execute("UPDATE rf_clearances SET state='withdrawn', reasons=? WHERE id=?",
                   (reason, row['id']))
    return len(rows)


def _invalidate_evidence(db, site, config, kind):
    receipts = many(db, '''SELECT id FROM rf_receipts WHERE site=? AND config IS ?
                           AND state='accepted' ''', (site, config))
    for row in receipts:
        db.execute("UPDATE rf_receipts SET state='invalidated', note=? WHERE id=?",
                   (kind, row['id']))
    submissions = many(db, '''SELECT id FROM rf_submissions WHERE site=? AND config IS ?
                              AND state='filed' ''', (site, config))
    for row in submissions:
        db.execute("UPDATE rf_submissions SET state='invalidated' WHERE id=?",
                   (row['id'],))
    return {'receipts': len(receipts), 'submissions': len(submissions)}


def _action(db, x):
    op_id = x['id']
    site = one(db, 'SELECT * FROM rf_sites WHERE site=?', (x['site'],))
    if not site:
        return {'decision': 'unknown_site'}
    kind = x['kind']
    is_rollback = kind in ROLLBACK_KINDS
    branch = x.get('branch')
    if is_rollback:
        branch = branch or 'in_place'
        if branch not in BRANCH_REQUIRED:
            return {'decision': 'unknown_branch'}
    else:
        expected = ACTION_BRANCH.get(kind)
        if not expected:
            return {'decision': 'unknown_action_kind'}
        if branch and branch != expected:
            return {'decision': 'action_branch_mismatch', 'expected': expected}
        branch = expected
    if not x.get('config_before') or not x.get('config_after'):
        return {'decision': 'configuration_required'}
    if x['config_before'] == x['config_after']:
        return {'decision': 'no_configuration_change'}

    previous = _latest_action(db, x['site'], branch)
    last_rollback = _last_rollback(db, x['site'], branch)
    if previous and x['config_before'] != previous['config_after']:
        return {'decision': 'configuration_discontinuity',
                'expected': previous['config_after']}
    if x.get('at') is None:
        return {'decision': 'action_time_required'}
    if previous and x['at'] < previous['at']:
        return {'decision': 'stale_action'}
    if last_rollback and last_rollback['at'] > x['at']:
        return {'decision': 'stale_action'}

    if kind == 'relocate_carrier_antenna':
        permit = one(db, 'SELECT * FROM rf_permits WHERE id=?',
                     (x.get('permit'),))
        if not permit or permit['state'] != 'active':
            return {'decision': 'permit_required'}
        if permit['site'] != x['site'] or permit['position'] != x.get('position'):
            return {'decision': 'permit_position_mismatch'}
        if not str(permit['position']).startswith('roof'):
            return {'decision': 'permit_position_not_licensed_roof'}
    if kind == 'migrate_resolution':
        if x.get('cabinet_state') != 'accepted':
            return {'decision': 'cabinet_not_accepted'}
        if x.get('uplink') != 'up':
            return {'decision': 'uplink_unverified'}

    db.execute('''INSERT INTO rf_actions
                  (id,site,branch,kind,config_before,config_after,at,permit,
                   cabinet,position,uplink,detail,state)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)''',
               (op_id, x['site'], branch, kind, x['config_before'],
                x['config_after'], x.get('at'), x.get('permit'),
                x.get('cabinet'), x.get('position'), x.get('uplink'),
                x.get('detail'), 'committed'))
    withdrawn = _withdraw_config_clearances(db, x['site'], x['config_before'],
                                            'configuration_changed')
    invalidated = {'receipts': 0, 'submissions': 0}
    if is_rollback:
        invalidated = _invalidate_evidence(db, x['site'], x['config_before'],
                                           'rolled_back')
        restored = _invalidate_evidence(db, x['site'], x['config_after'],
                                        'restored_configuration')
        invalidated['receipts'] += restored['receipts']
        invalidated['submissions'] += restored['submissions']
        _withdraw_config_clearances(db, x['site'], x['config_after'],
                                    'rolled_back_configuration')
    return {'decision': 'rolled_back' if is_rollback else 'action_committed',
            'branch': branch, 'config_after': x['config_after'],
            'withdrawn_clearances': withdrawn, 'invalidated': invalidated}


def _retest(db, x):
    action = one(db, 'SELECT * FROM rf_actions WHERE id=?', (x['action'],))
    if not action or action['state'] != 'committed':
        return {'decision': 'unknown_action'}
    if action['kind'] in ROLLBACK_KINDS:
        return {'decision': 'rollback_action_not_retestable'}
    if x['config'] != action['config_after']:
        return {'decision': 'retest_config_mismatch',
                'expected': action['config_after']}
    if x.get('at') is not None and x['at'] < action['at']:
        return {'decision': 'retest_before_action'}
    rollback = _last_rollback(db, action['site'], action['branch'])
    if rollback and rollback['at'] >= action['at']:
        return {'decision': 'action_rolled_back'}
    if action['kind'] == 'relocate_carrier_antenna':
        permit = one(db, 'SELECT * FROM rf_permits WHERE id=?',
                     (action['permit'],))
        if not permit or permit['state'] != 'active':
            return {'decision': 'permit_revoked'}
    receiver = one(db, 'SELECT * FROM rf_receivers WHERE id=?',
                   (x.get('receiver'),))
    if not receiver or receiver['site'] != action['site']:
        return {'decision': 'unknown_receiver'}
    if receiver['config'] != x['config']:
        # The neighbour's acceptance conditions were fixed for another
        # equipment state; they must be re-registered before they can judge.
        return {'decision': 'receiver_acceptance_config_stale',
                'registered_config': receiver['config'],
                'measured_config': x['config']}
    position = x.get('position', receiver['position'])
    if position != receiver['position']:
        return {'decision': 'measurement_point_mismatch',
                'required': receiver['position']}
    if x.get('mode') == 'full_shutdown_matrix':
        return {'decision': 'verification_interrupts_both_parties'}
    if x.get('mode') not in ('local_joint_spike', 'local_single_device'):
        return {'decision': 'unknown_retest_mode'}
    if x.get('errors', -1) < 0 or x.get('baseline', 0) < 0:
        return {'decision': 'invalid_retest_measurement'}
    if x.get('mode') == 'local_joint_spike':
        if not x.get('psu_on') or not x.get('carrier_on'):
            return {'decision': 'joint_spike_requires_both_devices'}
        if not x.get('local_neighbor', True) or not x.get('local_customer', True):
            return {'decision': 'joint_spike_requires_local_service'}

    done = {row['kind'] for row in _branch_actions(db, action['site'],
                                                   action['branch'])}
    missing = [kind for kind in BRANCH_REQUIRED[action['branch']]
               if kind not in done]
    if missing:
        return {'decision': 'branch_actions_incomplete', 'missing': missing}

    if not x.get('instrument') or x.get('calibrated_until') is None:
        return {'decision': 'instrument_calibration_unverified'}
    if x['at'] > x['calibrated_until']:
        return {'decision': 'instrument_calibration_expired'}

    passed = x['errors'] <= receiver['required_errors']
    db.execute('''INSERT INTO rf_retests
                  (id,action,site,branch,config,mode,receiver,position,psu_on,
                   carrier_on,errors,baseline,instrument,calibrated_until,
                   local_neighbor,local_customer,at,state)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
               (x['id'], action['id'], action['site'], action['branch'],
                x['config'], x.get('mode', 'local_joint_spike'),
                receiver['id'], position, int(bool(x.get('psu_on'))),
                int(bool(x.get('carrier_on'))), x['errors'],
                x.get('baseline', 0), x.get('instrument'),
                x.get('calibrated_until'), int(bool(x.get('local_neighbor', True))),
                int(bool(x.get('local_customer', True))), x.get('at'),
                'passed' if passed else 'failed'))
    if not passed:
        return {'decision': 'retest_failed', 'errors': x['errors'],
                'acceptance': receiver['required_errors']}
    return {'decision': 'retest_passed', 'config': x['config'],
            'position': position, 'receiver': receiver['id']}


def _neighbor(db, x):
    action = one(db, 'SELECT * FROM rf_actions WHERE id=?', (x['action'],))
    if not action:
        return {'decision': 'unknown_action'}
    if action['kind'] in ROLLBACK_KINDS:
        # A rollback is the opposite of an engineering remedy; it cannot carry
        # a neighbour acceptance, regardless of any retest referenced.
        return {'decision': 'rollback_action_not_signable'}
    retest = one(db, 'SELECT * FROM rf_retests WHERE id=?', (x.get('retest'),))
    if not retest or retest['action'] != action['id']:
        return {'decision': 'unknown_retest'}
    if retest['config'] != action['config_after']:
        return {'decision': 'retest_config_mismatch'}
    receiver = _latest_receiver(db, action['site'])
    if not receiver:
        return {'decision': 'unknown_receiver'}
    if x.get('receiver', retest['receiver']) != retest['receiver']:
        return {'decision': 'receiver_mismatch',
                'expected': retest['receiver']}
    if receiver['config'] != retest['config']:
        return {'decision': 'receiver_acceptance_config_stale',
                'registered_config': receiver['config'],
                'measured_config': retest['config']}
    if x.get('position', receiver['position']) != receiver['position']:
        return {'decision': 'measurement_point_mismatch',
                'required': receiver['position']}
    rollback = _last_rollback(db, action['site'], action['branch'])
    if rollback and rollback['at'] >= action['at']:
        return {'decision': 'action_rolled_back'}

    decision = x.get('decision', 'accepted')
    if not x.get('signer'):
        return {'decision': 'signer_required'}
    if decision == 'accepted' and retest['state'] != 'passed':
        return {'decision': 'retest_not_passed'}
    if decision not in ('accepted', 'rejected'):
        return {'decision': 'unknown_neighbor_decision'}
    db.execute('''INSERT INTO rf_receipts
                  (id,action,site,party,retest,config,position,at,signer,
                   state,capacity_mbps,latency_ms,uplink,note)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
               (x['id'], action['id'], action['site'], 'neighbor',
                retest['id'], retest['config'], receiver['position'],
                x.get('at'), x.get('signer'), decision, None, None, None,
                x.get('note')))
    if decision == 'rejected':
        return {'decision': 'neighbor_rejected'}
    return {'decision': 'neighbor_accepted', 'config': retest['config'],
            'position': receiver['position']}


def _customer(db, x):
    action = one(db, 'SELECT * FROM rf_actions WHERE id=?', (x['action'],))
    if not action:
        return {'decision': 'unknown_action'}
    if action['kind'] in ROLLBACK_KINDS:
        return {'decision': 'rollback_action_not_signable'}
    retest = one(db, 'SELECT * FROM rf_retests WHERE id=?', (x.get('retest'),))
    if not retest or retest['action'] != action['id']:
        return {'decision': 'unknown_retest'}
    if retest['config'] != action['config_after']:
        return {'decision': 'retest_config_mismatch'}
    site = one(db, 'SELECT * FROM rf_sites WHERE site=?', (action['site'],))
    if x.get('receiver', retest['receiver']) != retest['receiver']:
        return {'decision': 'receiver_mismatch',
                'expected': retest['receiver']}
    rollback = _last_rollback(db, action['site'], action['branch'])
    if rollback and rollback['at'] >= action['at']:
        return {'decision': 'action_rolled_back'}
    if not x.get('signer'):
        return {'decision': 'signer_required'}
    capacity = x.get('capacity_mbps')
    latency = x.get('latency_ms')
    if capacity is None or capacity < site['customer_capacity_mbps']:
        return {'decision': 'customer_capacity_below_contract',
                'contracted': site['customer_capacity_mbps']}
    if x.get('uplink') != 'up':
        return {'decision': 'customer_uplink_unavailable'}
    if site['customer_latency_ms'] is not None:
        if latency is None:
            return {'decision': 'customer_latency_unverified',
                    'contracted': site['customer_latency_ms']}
        if latency > site['customer_latency_ms']:
            return {'decision': 'customer_latency_above_contract',
                    'contracted': site['customer_latency_ms']}
    if retest['state'] != 'passed':
        return {'decision': 'retest_not_passed'}
    db.execute('''INSERT INTO rf_receipts
                  (id,action,site,party,retest,config,position,at,signer,
                   state,capacity_mbps,latency_ms,uplink,note)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
               (x['id'], action['id'], action['site'], 'customer',
                retest['id'], retest['config'], retest['position'],
                x.get('at'), x.get('signer'), 'accepted', capacity, latency,
                x.get('uplink'), x.get('note')))
    return {'decision': 'customer_confirmed', 'config': retest['config'],
            'capacity_mbps': capacity, 'latency_ms': latency}


def _submit(db, x):
    action = one(db, 'SELECT * FROM rf_actions WHERE id=?', (x['action'],))
    if not action or action['state'] != 'committed':
        return {'decision': 'unknown_action'}
    if action['kind'] in ROLLBACK_KINDS:
        return {'decision': 'rollback_action_not_submittable'}
    receiver = _latest_receiver(db, action['site'])
    if not receiver:
        return {'decision': 'unknown_receiver'}
    if receiver['config'] != action['config_after']:
        return {'decision': 'receiver_acceptance_config_stale',
                'registered_config': receiver['config'],
                'measured_config': action['config_after']}
    retest = _valid_retest(db, action['id'], action['config_after'],
                           -1 if action['at'] is None else action['at'])
    if not retest:
        return {'decision': 'submission_requires_passed_retest'}
    receipt = _receipt(db, action['id'], 'neighbor')
    if not receipt:
        return {'decision': 'submission_requires_neighbor_acceptance'}
    position = x.get('position', receiver['position'])
    if (position != receiver['position'] or receipt['position'] != position
            or retest['position'] != position):
        return {'decision': 'submission_config_mismatch',
                'reason': 'measurement_point_differs'}
    if (x.get('config') != action['config_after']
            or receipt['config'] != action['config_after']
            or retest['config'] != action['config_after']):
        return {'decision': 'submission_config_mismatch',
                'reason': 'configuration_differs'}
    customer = _receipt(db, action['id'], 'customer')
    if not customer or customer['config'] != action['config_after']:
        # A submission that ignores the customer's contracted capacity would
        # let a silent downgrade be filed as a resolved incident.
        return {'decision': 'submission_requires_customer_confirmation'}
    latest = _latest_action(db, action['site'], action['branch'])
    if latest and latest['id'] != action['id']:
        return {'decision': 'submission_config_mismatch',
                'reason': 'later_configuration'}
    rollback = _last_rollback(db, action['site'], action['branch'])
    if rollback and rollback['at'] >= action['at']:
        return {'decision': 'action_rolled_back'}
    db.execute('''INSERT INTO rf_submissions
                  (id,action,site,config,position,at,body,state)
                  VALUES(?,?,?,?,?,?,?,?)''',
               (x['id'], action['id'], action['site'], action['config_after'],
                position, x.get('at'), x.get('body'), 'filed'))
    return {'decision': 'submission_filed', 'config': action['config_after'],
            'position': position}


def _branch_state(db, site, branch):
    actions = _branch_actions(db, site, branch)
    latest = _latest_action(db, site, branch)
    rollback = _last_rollback(db, site, branch)
    receiver = _latest_receiver(db, site)
    kinds = {row['kind'] for row in actions}
    missing = [kind for kind in BRANCH_REQUIRED[branch] if kind not in kinds]
    info = {
        'branch': branch,
        'actions': [row['kind'] for row in actions],
        # A rollback is an action of this branch too, but it does not satisfy
        # an engineering prerequisite: it reopens the old configuration.
        'missing_actions': missing,
        'differences': BRANCH_DIFFERENCES[branch],
        'config': latest['config_after'] if latest else None,
        'blockers': [],
        'retest': None, 'neighbor_receipt': None,
        'customer_receipt': None, 'submission': None,
    }
    if rollback and (not latest or rollback['at'] >= latest['at']):
        info['state'] = 'rolled_back'
        info['blockers'].append('rolled_back')
        return info
    if not actions:
        info['state'] = 'available'
        info['blockers'].append('no_engineering_action')
        return info
    if missing:
        info['state'] = 'planned'
        info['blockers'].append('branch_actions_incomplete')
        return info
    config = latest['config_after']
    # A retest from before the latest action (or before a rollback) measured a
    # different physical state; it cannot be reused for the current one.
    after = -1 if latest['at'] is None else latest['at']
    retest = _valid_retest(db, latest['id'], config, after)
    if not retest:
        info['state'] = 'awaiting_retest'
        info['blockers'].append('no_passing_local_joint_spike_retest')
        for row in actions:
            if row['kind'] in ROLLBACK_KINDS:
                continue
            candidate = _valid_retest(db, row['id'], config, after)
            if candidate:
                retest = candidate
                break
    if retest:
        info['retest'] = {'id': retest['id'], 'config': retest['config'],
                          'position': retest['position'],
                          'errors': retest['errors']}
    retest_action = retest['action'] if retest else latest['id']
    neighbor = _receipt(db, retest_action, 'neighbor')
    customer = _receipt(db, retest_action, 'customer')
    if neighbor:
        info['neighbor_receipt'] = {'id': neighbor['id'],
                                    'config': neighbor['config'],
                                    'position': neighbor['position']}
    if customer:
        info['customer_receipt'] = {'id': customer['id'],
                                    'config': customer['config'],
                                    'capacity_mbps': customer['capacity_mbps'],
                                    'latency_ms': customer['latency_ms']}
    if not retest:
        return info
    if not neighbor:
        info['state'] = 'awaiting_neighbor_acceptance'
        info['blockers'].append('neighbor_not_signed')
        return info
    if not customer:
        info['state'] = 'awaiting_customer_confirmation'
        info['blockers'].append('customer_not_signed')
        return info
    if not receiver:
        info['state'] = 'awaiting_retest'
        info['blockers'].append('receiver_not_registered')
        return info
    submission = _submission(db, retest_action, config,
                             receiver['position'])
    if submission:
        info['submission'] = {'id': submission['id'],
                              'config': submission['config'],
                              'position': submission['position']}
    if not submission:
        info['state'] = 'awaiting_regulator_submission'
        info['blockers'].append('regulator_submission_missing_or_mismatched')
        return info
    info['state'] = 'delivered'
    return info


def _resolution(db, x):
    site_name = x['site']
    site = one(db, 'SELECT * FROM rf_sites WHERE site=?', (site_name,))
    if not site:
        return {'decision': 'unknown_site'}
    receiver = _latest_receiver(db, site_name)
    branches = {branch: _branch_state(db, site_name, branch)
                for branch in ('in_place', 'separation')}
    complete = [branch for branch, info in branches.items()
                if info['state'] == 'delivered']
    selected = complete[0] if complete else None

    experiment = one(db, 'SELECT * FROM rf_experiments WHERE site=? '
                         'ORDER BY at DESC, rowid DESC LIMIT 1', (site_name,))
    attribution = None
    if experiment:
        attribution = {
            'experiment': experiment['id'],
            'verdict': experiment['verdict'],
            'attribution': 'not_attributable_to_single_source',
            'candidates': _loads(experiment['candidates']),
            'ruled_out': _loads(experiment['ruled_out']),
            'deltas': _loads(experiment['deltas']),
            'single_action': _loads(experiment['single_action']),
            'blockers': _loads(experiment['blockers']),
        }

    clearances = many(db, 'SELECT * FROM rf_clearances WHERE site=? '
                          'ORDER BY rowid', (site_name,))
    clearance_states = []
    provisional_clear = False
    for row in clearances:
        state = rf_clearance.status(db, row['id'])
        clearance_states.append({'id': row['id'], 'config': row['config'],
                                 'decision': state['decision'],
                                 'reasons': state['reasons']})
        if state['decision'] == 'clear':
            provisional_clear = True

    configurations = ({row['config_after'] for row in
                       many(db, 'SELECT DISTINCT config_after FROM rf_actions '
                                'WHERE site=?', (site_name,))}
                      | {row['config_before'] for row in
                         many(db, 'SELECT DISTINCT config_before FROM rf_actions '
                                  'WHERE site=?', (site_name,))}
                      | {row['config'] for row in clearances if row['config']}
                      | {row['config'] for row in
                         many(db, 'SELECT DISTINCT config FROM rf_samples '
                                  'WHERE site=?', (site_name,)) if row['config']})
    configurations = sorted(configurations)
    windows = []
    for config in configurations:
        covered = any(
            info['state'] == 'delivered' and info['config'] == config
            for info in branches.values())
        window = {'site': site_name, 'config': config}
        if covered:
            window.update(state='verified',
                          reason='passing local retest and both signatures '
                                 'on this measurement configuration')
        else:
            window.update(state='unverified',
                          reason='no current passing retest and signatures')
        windows.append(window)
    if not windows:
        for row in clearance_states:
            windows.append({
                'site': site_name, 'config': row['config'],
                'state': 'unverified' if row['decision'] != 'clear' else 'provisional',
                'reason': 'clearance_not_assertable' if row['decision'] != 'clear'
                          else 'provisional release only; no retest or signatures'})

    neighbor_service = 'unverified'
    if selected:
        neighbor_service = 'accepted_at_original_position_after_retest'
    elif provisional_clear:
        neighbor_service = 'provisional_only'
    customer_service = 'unavailable_or_unverified'
    if selected:
        customer_service = 'contracted_service_confirmed'
    elif provisional_clear:
        customer_service = 'provisional_only'
    elif any(info['state'] == 'awaiting_customer_confirmation'
             for info in branches.values()):
        customer_service = 'awaiting_customer_confirmation'

    invalidated_receipts = many(db, '''SELECT id,party,config,note FROM rf_receipts
                                       WHERE site=? AND state='invalidated'
                                       ORDER BY rowid''', (site_name,))
    invalidated_submissions = many(db, '''SELECT id,config FROM rf_submissions
                                          WHERE site=? AND state='invalidated'
                                          ORDER BY rowid''', (site_name,))
    delivery = {
        'state': 'delivered' if selected else 'not_delivered',
        'branch': selected,
        'config': branches[selected]['config'] if selected else None,
        'both_parties_signed': bool(selected),
        'same_measured_config': bool(selected),
        'complete_branches': complete,
        'selection_basis': (
            "retest plus both parties' signatures on one measured "
            'configuration' if selected else
            'a branch is delivered only after action, joint-spike retest, '
            'neighbour acceptance and customer capacity confirmation'
        ),
    }
    return {
        'decision': 'resolution_reported',
        'site': site_name,
        # No static interference label is produced: the 2x2 diagnosis lists
        # candidates and the open discriminators that field retests must close.
        'static_label': None,
        'attribution': attribution,
        'branches': branches,
        'delivery': delivery,
        'neighbor_service': neighbor_service,
        'customer_service': customer_service,
        'clearances': clearance_states,
        'windows': windows,
        'invalidated_receipts': invalidated_receipts,
        'invalidated_submissions': invalidated_submissions,
        'measured_position': receiver['position'] if receiver else None,
        'contract': {
            'neighbor_capacity_mbps': site['neighbor_capacity_mbps'],
            'customer_capacity_mbps': site['customer_capacity_mbps'],
            'customer_latency_ms': site['customer_latency_ms'],
        },
    }


def handle(db, x):
    op = x.get('op')
    if op == 'site':
        if (x['customer_capacity_mbps'] <= 0
                or x['neighbor_capacity_mbps'] <= 0):
            return {'decision': 'invalid_contract'}
        old = one(db, 'SELECT * FROM rf_sites WHERE site=?', (x['site'],))
        if old:
            same = (old['neighbor_site'] == x.get('neighbor_site')
                    and old['neighbor_capacity_mbps'] == x['neighbor_capacity_mbps']
                    and old['customer_capacity_mbps'] == x['customer_capacity_mbps']
                    and old['customer_latency_ms'] == x.get('customer_latency_ms'))
            if not same:
                return {'decision': 'site_contract_identity_conflict'}
            return {'decision': 'site_registered'}
        db.execute('''INSERT INTO rf_sites
                      (site,neighbor_site,neighbor_capacity_mbps,
                       customer_capacity_mbps,customer_latency_ms,state)
                      VALUES(?,?,?,?,?,?)''',
                   (x['site'], x.get('neighbor_site'),
                    x['neighbor_capacity_mbps'], x['customer_capacity_mbps'],
                    x.get('customer_latency_ms'), 'active'))
        return {'decision': 'site_registered'}

    if op == 'receiver':
        if not x.get('position') or not x.get('config'):
            return {'decision': 'receiver_evidence_required'}
        if x['required_errors'] < 0:
            return {'decision': 'invalid_acceptance'}
        old = one(db, 'SELECT * FROM rf_receivers WHERE id=?', (x['id'],))
        if old:
            if old['site'] != x['site']:
                return {'decision': 'receiver_site_mismatch'}
            if old['position'] != x['position']:
                # The neighbour's original receive position is the acceptance
                # point.  A rebuilt equipment state may change the acceptance
                # threshold, but not where acceptance is measured.
                return {'decision': 'receiver_position_changed',
                        'original_position': old['position']}
            if x.get('at') is None or old['at'] is not None and x['at'] < old['at']:
                return {'decision': 'stale_receiver'}
            db.execute('''UPDATE rf_receivers SET position=?,config=?,
                          required_errors=?,at=? WHERE id=?''',
                       (x['position'], x['config'], x['required_errors'],
                        x['at'], x['id']))
            return {'decision': 'receiver_reregistered',
                    'position': x['position'], 'config': x['config']}
        db.execute('''INSERT INTO rf_receivers
                      (id,site,position,config,required_errors,state,at)
                      VALUES(?,?,?,?,?,?,?)''',
                   (x['id'], x['site'], x['position'], x['config'],
                    x['required_errors'], 'registered', x.get('at')))
        return {'decision': 'receiver_registered', 'position': x['position']}

    if op == 'permit':
        state = x.get('state', 'active')
        if state not in ('active', 'revoked'):
            return {'decision': 'invalid_permit_state'}
        old = one(db, 'SELECT * FROM rf_permits WHERE id=?', (x['id'],))
        if old:
            if old['site'] != x['site'] or old['position'] != x['position']:
                return {'decision': 'permit_identity_conflict'}
            if x.get('at') is None or (old['at'] is not None
                                       and x['at'] < old['at']):
                return {'decision': 'stale_permit'}
            db.execute('''UPDATE rf_permits SET issuer=?, at=?, state=?
                          WHERE id=?''',
                       (x.get('issuer', old['issuer']), x.get('at'), state,
                        x['id']))
            return {'decision': 'permit_active' if state == 'active'
                    else 'permit_revoked'}
        db.execute('''INSERT INTO rf_permits
                      (id,site,position,issuer,at,state) VALUES(?,?,?,?,?,?)''',
                   (x['id'], x['site'], x['position'], x.get('issuer'),
                    x.get('at'), state))
        return {'decision': 'permit_registered'}

    if op == 'sample':
        if x['field_mv'] < 0 or x['frequency_khz'] <= 0:
            return {'decision': 'invalid_sample'}
        load = x.get('load_pct', 0)
        if not 0 <= load <= 100:
            return {'decision': 'invalid_load'}
        if x.get('calibrated_until') is None:
            return {'decision': 'instrument_calibration_unverified'}
        if x.get('bandwidth_khz', 0) <= 0:
            return {'decision': 'bandwidth_unspecified'}
        if not x.get('antenna') or not x.get('point'):
            return {'decision': 'antenna_or_point_required'}
        rf_survey.record(db, x['id'], x['site'], x['frequency_khz'],
                         x.get('at'), x['field_mv'], x.get('instrument'),
                         x.get('bandwidth_khz'),
                         x.get('calibrated_until'), x.get('antenna'),
                         x.get('point'), x.get('load_pct', 0),
                         x.get('config'))
        return {'decision': 'sample_recorded', 'config': x.get('config'),
                'point': x.get('point')}

    if op == 'provisional':
        state = rf_clearance.provisional(
            db, x['id'], x['site'], x['frequency_khz'], x['limit_mv'],
            x.get('config'), x.get('point'), x.get('at'))
        status = rf_clearance.status(db, x['id'])
        return {'decision': state, 'reasons': status['reasons'],
                'config': x.get('config'), 'point': x.get('point')}

    if op == 'withdraw_clearance':
        return rf_clearance.withdraw(db, x['id'], x.get('reason', 'withdrawn'))

    if op == 'clearance_status':
        return rf_clearance.status(db, x['id'])

    if op == 'trial':
        if x['errors'] < 0 or x.get('baseline', 0) < 0:
            return {'decision': 'invalid_trial'}
        if not 0 <= x.get('load_pct', 0) <= 100:
            return {'decision': 'invalid_load'}
        rf_trial.observe(db, x['id'], x['site'], x['psu_on'], x['carrier_on'],
                         x.get('load_pct', 0), x['errors'], x.get('at'),
                         x.get('receiver'), x.get('config'),
                         x.get('baseline', 0), x['experiment'])
        return {'decision': 'trial_recorded',
                'combination': [int(bool(x['psu_on'])),
                                int(bool(x['carrier_on']))]}

    if op == 'diagnose':
        result = _diagnose(db, x)
        if result['decision'] == 'diagnosed':
            _record_diagnosis(db, x, result)
        return result

    if op == 'spectrum':
        db.execute('''INSERT INTO rf_spectrum
                      (id,site,config,frequency_khz,peak_mv,tracks,at,attribution)
                      VALUES(?,?,?,?,?,?,?,?)''',
                   (x['id'], x['site'], x.get('config'), x.get('frequency_khz'),
                    x.get('peak_mv'), x.get('tracks', 'unknown'), x.get('at'),
                    'supporting_only'))
        return {'decision': 'spectrum_recorded', 'attribution': 'not_from_spectrum'}

    if op == 'action':
        return _action(db, x)

    if op == 'retest':
        return _retest(db, x)

    if op == 'neighbor':
        return _neighbor(db, x)

    if op == 'customer':
        return _customer(db, x)

    if op == 'submit':
        return _submit(db, x)

    if op == 'regulator_withdraw':
        submission = one(db, 'SELECT * FROM rf_submissions WHERE id=?',
                         (x.get('submission'),))
        if not submission or submission['state'] != 'filed':
            return {'decision': 'unknown_submission'}
        db.execute("UPDATE rf_submissions SET state='withdrawn' WHERE id=?",
                   (submission['id'],))
        withdrawn = _withdraw_config_clearances(
            db, submission['site'], submission['config'], 'regulator_withdrawn')
        return {'decision': 'submission_withdrawn',
                'withdrawn_clearances': withdrawn}

    if op == 'resolution':
        return _resolution(db, x)

    return {'decision': 'unknown_operation'}


def run(db, x):
    return act(db, 'rf', x, handle)
