import sqlite3
import unittest

from cloudcourt.rf_trial import observe, provisional_cause


class RfTrialSeedTest(unittest.TestCase):
    def test_interaction_is_misattributed_to_single_device(self):
        db = sqlite3.connect(':memory:')
        observe(db, 'T1', 'S', True, True, 90, 100, 1)
        observe(db, 'T2', 'S', False, True, 90, 60, 2)
        observe(db, 'T3', 'S', True, False, 90, 65, 3)
        observe(db, 'T4', 'S', False, False, 90, 0, 4)
        observe(db, 'T5', 'S', True, True, 90, 110, 5)
        self.assertEqual('psu', provisional_cause(db, 'S'))
        db.close()


if __name__ == '__main__':
    unittest.main()
