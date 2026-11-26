import tempfile
import unittest
from pathlib import Path
from cloudcourt.store import connect
from cloudcourt.dns_research import submit
from cloudcourt.research_award import provisional_award


class ResearchSeedTest(unittest.TestCase):
    def test_report_changes_provisional_award(self):
        with tempfile.TemporaryDirectory() as folder:
            db=connect(str(Path(folder)/'state.sqlite'))
            self.assertEqual(provisional_award(db,'a','r',10)['decision'],'unavailable')
            submit(db,'r','finder','zone.example','digest',3)
            self.assertEqual(provisional_award(db,'a','r',10)['amount'],30)
            db.close()
