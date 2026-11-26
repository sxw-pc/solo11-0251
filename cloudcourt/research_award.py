"""Draft a provisional research award from a submitted report."""
from .store import tx


def provisional_award(db,award_id,report_id,unit):
    with tx(db):
        db.execute('CREATE TABLE IF NOT EXISTS dns_research(id TEXT PRIMARY KEY,finder TEXT,zone TEXT,proof_digest TEXT,impact INTEGER)')
        db.execute('CREATE TABLE IF NOT EXISTS research_awards(id TEXT PRIMARY KEY,report TEXT,amount INTEGER)')
        old=db.execute('SELECT amount FROM research_awards WHERE id=?',(award_id,)).fetchone()
        if old:return {'decision':'reused','amount':old['amount']}
        report=db.execute('SELECT impact FROM dns_research WHERE id=?',(report_id,)).fetchone()
        if not report or unit<0:return {'decision':'unavailable'}
        amount=report['impact']*unit
        db.execute('INSERT INTO research_awards VALUES (?,?,?)',(award_id,report_id,amount))
        return {'decision':'offered','amount':amount}
