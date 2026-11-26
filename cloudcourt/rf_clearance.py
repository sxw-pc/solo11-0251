"""Provisional RF clearance backed by configuration-scoped evidence.

A provisional release is never derived from "the latest reading".  It is bound
to one measured equipment configuration and one physical measurement point.
Within that scope the clearance is ``blocked`` as soon as any admissible sample
at or above the limit is on record, even if a later no-load reading is low:
idle readings cannot erase a high-load exceedance.

The release is provisional service only.  It says nothing about the neighbour's
acceptance or the customer's contracted capacity; those are recorded as
separate receipts by :mod:`cloudcourt.rf_resolution`.
"""

from . import rf_survey

SCHEMA = '''
CREATE TABLE IF NOT EXISTS rf_clearances(
    id TEXT PRIMARY KEY, site TEXT, frequency_khz INTEGER,
    sample_id TEXT, state TEXT,
    config TEXT, point TEXT, limit_mv INTEGER, reasons TEXT, created_at INTEGER
);
'''


def ensure(db):
    for statement in SCHEMA.split(';'):
        if statement.strip():
            db.execute(statement)


def _reasons(samples, limit_mv, at, config, point):
    reasons = []
    if not samples:
        reasons.append('no_sample_for_config')
        return reasons
    if point is None:
        reasons.append('measurement_point_unspecified')
    selected = [s for s in samples if point is None or s['point'] == point]
    if not selected:
        reasons.append('no_sample_at_point')
        return reasons
    if any(s['at'] > (s['calibrated_until'] if s['calibrated_until'] is not None
                      else -1) for s in selected):
        reasons.append('instrument_calibration_expired')
    if any(s['bandwidth_khz'] in (None, 0) for s in selected):
        reasons.append('bandwidth_unspecified')
    if any(s['antenna'] in (None, '') for s in selected):
        reasons.append('antenna_orientation_unspecified')
    if any(s['config'] != config for s in selected):
        reasons.append('configuration_mismatch')
    if any(s['load_pct'] is None or not 0 <= s['load_pct'] <= 100
           for s in selected):
        reasons.append('load_value_invalid')
    exceed = [s for s in selected if s['field_mv'] > limit_mv]
    if exceed:
        high_load = any(s['field_mv'] > limit_mv and s['load_pct'] > 0
                        for s in selected)
        reasons.append('high_load_exceedance' if high_load else 'field_exceeds_limit')
    if not any(s['load_pct'] > 0 for s in selected):
        reasons.append('no_loaded_measurement')
    if config is None:
        reasons.append('configuration_unspecified')
    if at is not None and any(s['at'] > at for s in selected):
        # A release cannot rest on a reading taken after it was issued.
        reasons.append('sample_after_clearance_time')
    # A clearance at one point must not ignore an exceedance at another point
    # of the same measured configuration: the neighbour's band is not confined
    # to the point a technician happened to choose.
    if point is not None:
        elsewhere = [s for s in samples if s['point'] != point
                     and s['field_mv'] > limit_mv]
        if elsewhere:
            reasons.append('exceedance_at_other_point')
    return reasons


def provisional(db, clearance_id, site, frequency_khz, limit_mv,
                config=None, point=None, at=None):
    """Issue a provisional release for one configuration and measurement point."""
    rf_survey.ensure(db)
    ensure(db)
    samples = rf_survey.for_config(db, site, config)
    samples = [s for s in samples if s['frequency_khz'] == frequency_khz]
    effective_at = at
    if effective_at is None and samples:
        effective_at = max(s['at'] for s in samples)
    reasons = _reasons(samples, limit_mv, effective_at, config, point)
    state = 'clear' if not reasons else 'blocked'
    at_point = [s for s in samples if s['point'] == point]
    evidence = at_point[0]['id'] if at_point else (samples[0]['id'] if samples else None)
    db.execute(
        'INSERT INTO rf_clearances VALUES(?,?,?,?,?,?,?,?,?,?)',
        (clearance_id, site, frequency_khz, evidence, state, config, point,
         limit_mv, ','.join(reasons), effective_at))
    return state


def status(db, clearance_id):
    """Current status, re-evaluated against the record; stale config is invalid."""
    rf_survey.ensure(db)
    ensure(db)
    row = db.execute('SELECT * FROM rf_clearances WHERE id=?',
                     (clearance_id,)).fetchone()
    if not row:
        return {'decision': 'unknown_clearance'}
    row = dict(row)
    samples = [s for s in rf_survey.for_config(db, row['site'], row['config'])
               if s['frequency_khz'] == row['frequency_khz']]
    # Re-evaluation is not a new issue: later monitoring samples must not
    # retroactively block a release, but an exceedance they carry will.
    reasons = _reasons(samples, row['limit_mv'], None,
                       row['config'], row['point'])
    if row['state'] == 'withdrawn':
        reasons.append('withdrawn')
    state = 'clear' if not reasons and row['state'] == 'clear' else 'blocked'
    return {'decision': state, 'reasons': reasons}


def withdraw(db, clearance_id, reason='withdrawn'):
    """Retire a release after the measured configuration has changed."""
    ensure(db)
    row = db.execute('SELECT id FROM rf_clearances WHERE id=?',
                     (clearance_id,)).fetchone()
    if not row:
        return {'decision': 'unknown_clearance'}
    db.execute("UPDATE rf_clearances SET state='withdrawn', reasons=? WHERE id=?",
               (reason, clearance_id))
    return {'decision': 'withdrawn'}
