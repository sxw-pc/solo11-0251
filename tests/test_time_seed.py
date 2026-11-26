import sqlite3
import unittest

from cloudcourt.clock_reference import observe
from cloudcourt.time_attestation import provisional


class TimeSeedTest(unittest.TestCase):
    def test_latest_reference_controls_provisional_time(self):
        db = sqlite3.connect(':memory:')
        observe(db, 'R1', 'site-1', 'gps-1', 10, 0, 2, 100)
        observe(db, 'R2', 'site-1', 'gps-2', 11, -5000, 2, 100)
        self.assertEqual(7000, provisional(db, 'A1', 'site-1', 'permit', 12000))
        db.close()


if __name__ == '__main__':
    unittest.main()
