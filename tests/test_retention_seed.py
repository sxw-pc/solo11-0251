import tempfile
import unittest
from pathlib import Path
from cloudcourt.store import connect
from cloudcourt.evidence_hold import hold
from cloudcourt.retention import provisional_purge


class RetentionSeedTest(unittest.TestCase):
    def test_hold_changes_provisional_purge(self):
        with tempfile.TemporaryDirectory() as folder:
            db=connect(str(Path(folder)/'state.sqlite'))
            db.execute('INSERT INTO flow_attempts VALUES (?,?,?,?,?,?,?)',('f','g','p','h','192.0.2.1',10,'settled'))
            self.assertEqual(provisional_purge(db,'p1')['flows'],['f'])
            hold(db,'h1','f','case-a')
            self.assertEqual(provisional_purge(db,'p2')['flows'],[])
            db.close()
