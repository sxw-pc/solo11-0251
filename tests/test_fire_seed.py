import sqlite3
import unittest

from cloudcourt.fire_sensor import report
from cloudcourt.suppression import indicate


class FireSeedTest(unittest.TestCase):
    def test_two_signals_set_provisional_ready_state(self):
        db = sqlite3.connect(':memory:')
        report(db, 'F1', 'resolver-room', 'D1', 'smoke', 10)
        report(db, 'F2', 'resolver-room', 'D1', 'heat', 11)
        self.assertEqual('ready', indicate(db, 'I1', 'resolver-room'))
        db.close()


if __name__ == '__main__':
    unittest.main()
