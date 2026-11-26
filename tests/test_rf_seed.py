import sqlite3
import unittest

from cloudcourt.rf_survey import record
from cloudcourt.rf_clearance import provisional


class RfSeedTest(unittest.TestCase):
    def test_later_low_value_clears_earlier_high_field(self):
        db = sqlite3.connect(':memory:')
        record(db, 'S1', 'site-1', 30000, 10, 90, 'probe-A')
        record(db, 'S2', 'site-1', 30000, 11, 10, 'probe-B')
        self.assertEqual('clear', provisional(db, 'C1', 'site-1', 30000, 50))
        db.close()


if __name__ == '__main__':
    unittest.main()
