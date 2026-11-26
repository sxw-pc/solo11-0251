"""A provisional heat delivery invoice based on a raw shared meter sum."""

from .plant_meter import total

SCHEMA = '''
CREATE TABLE IF NOT EXISTS heat_invoices(
    id TEXT PRIMARY KEY, site TEXT, buyer TEXT, start_at INTEGER,
    end_at INTEGER, billed_kwh INTEGER, state TEXT
);
'''


def provisional_invoice(db, invoice_id, site, buyer, start_at, end_at):
    db.executescript(SCHEMA)
    kwh = total(db, site, 'export', start_at, end_at)
    db.execute('INSERT INTO heat_invoices VALUES(?,?,?,?,?,?,?)',
               (invoice_id, site, buyer, start_at, end_at, kwh, 'provisional'))
    return kwh
