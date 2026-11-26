import sqlite3
import unittest

from cloudcourt.plant_meter import reading
from cloudcourt.heat_delivery import provisional_invoice


class HeatSeedTest(unittest.TestCase):
    def test_shared_export_meter_is_billed_twice(self):
        db = sqlite3.connect(':memory:')
        reading(db, 'M1', 'site-1', 'export', 0, 60, 100, 'C1')
        self.assertEqual(100, provisional_invoice(db, 'I1', 'site-1', 'buyer-A', 0, 60))
        self.assertEqual(100, provisional_invoice(db, 'I2', 'site-1', 'buyer-B', 0, 60))
        db.close()


if __name__ == '__main__':
    unittest.main()
