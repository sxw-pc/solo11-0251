import sqlite3
import unittest

from cloudcourt.fiber_route import receive
from cloudcourt.circuit_activation import provisional


class FiberSeedTest(unittest.TestCase):
    def test_two_route_ids_in_same_duct_are_called_diverse(self):
        db = sqlite3.connect(':memory:')
        receive(db, 'F1', 'carrier-A', 'duct-X', 'box-1', 40, 'blue')
        receive(db, 'F2', 'carrier-B', 'duct-X', 'box-1', 40, 'green')
        self.assertEqual('diverse', provisional(db, 'C1', 'tenant-A', 'F1', 'F2'))
        db.close()


if __name__ == '__main__':
    unittest.main()
