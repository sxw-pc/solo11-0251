import sqlite3
import unittest

from cloudcourt.image_build import record
from cloudcourt.image_delivery import provisional


class ImageSeedTest(unittest.TestCase):
    def test_different_toolchains_share_provisional_digest(self):
        db = sqlite3.connect(':memory:')
        first = record(db, 'B1', b'resolver source', 'compiler-1', 'release')
        second = record(db, 'B2', b'resolver source', 'compiler-2', 'release')
        self.assertEqual(first, second)
        self.assertEqual('accepted', provisional(db, 'D1', 'B2', 'customer-1', first))
        db.close()


if __name__ == '__main__':
    unittest.main()
