import sqlite3
import unittest

from cloudcourt.rf_trial import observe, provisional_cause


class RfTrialSeedTest(unittest.TestCase):
    def test_last_trial_shortcut_reports_single_device(self):
        db = sqlite3.connect(':memory:')
        observe(db, 'T1', 'S', True, True, 90, 100, 1)
        observe(db, 'T2', 'S', False, True, 90, 60, 2)
        observe(db, 'T3', 'S', True, False, 90, 65, 3)
        observe(db, 'T4', 'S', False, False, 90, 0, 4)
        observe(db, 'T5', 'S', True, True, 90, 110, 5)
        # The shortcut is retained only to show why it cannot be a resolution:
        # the last trial left both devices on, so it names the PSU alone.
        self.assertEqual('psu', provisional_cause(db, 'S'))
        db.close()


if __name__ == '__main__':
    unittest.main()
