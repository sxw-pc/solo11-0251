"""Provisional energy meter readings at resolver sites."""

SCHEMA = '''
CREATE TABLE IF NOT EXISTS plant_meters(
    id TEXT PRIMARY KEY, site TEXT, kind TEXT, start_at INTEGER, end_at INTEGER,
    kwh INTEGER, calibration TEXT
);
'''


def reading(db, meter_id, site, kind, start_at, end_at, kwh, calibration):
    db.executescript(SCHEMA)
    db.execute('INSERT INTO plant_meters VALUES(?,?,?,?,?,?,?)',
               (meter_id, site, kind, start_at, end_at, kwh, calibration))


def total(db, site, kind, start_at, end_at):
    db.executescript(SCHEMA)
    return db.execute('''SELECT COALESCE(SUM(kwh),0) FROM plant_meters
                         WHERE site=? AND kind=? AND start_at>=? AND end_at<=?''',
                      (site, kind, start_at, end_at)).fetchone()[0]
