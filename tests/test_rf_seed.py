import sqlite3
import unittest

from cloudcourt.rf_clearance import provisional, status
from cloudcourt.rf_survey import record


class RfSeedTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.common = dict(site='site-1', frequency_khz=30000, instrument='probe-A',
                           bandwidth_khz=200, calibrated_until=100,
                           antenna='sector-3-azimuth', point='neighbor-original',
                           config='cfg-1')

    def tearDown(self):
        self.db.close()

    def test_later_low_value_cannot_clear_earlier_high_load(self):
        record(self.db, 'S1', at=10, field_mv=90, load_pct=90, **self.common)
        record(self.db, 'S2', at=11, field_mv=10, load_pct=0, **self.common)
        self.assertEqual('blocked',
                         provisional(self.db, 'C1', 'site-1', 30000, 50,
                                     config='cfg-1', point='neighbor-original',
                                     at=12))
        self.assertIn('high_load_exceedance', status(self.db, 'C1')['reasons'])

    def test_loaded_low_value_clears(self):
        record(self.db, 'S1', at=10, field_mv=10, load_pct=90, **self.common)
        self.assertEqual('clear',
                         provisional(self.db, 'C1', 'site-1', 30000, 50,
                                     config='cfg-1', point='neighbor-original',
                                     at=12))

    def test_measurement_point_without_loaded_sample_is_not_clear(self):
        record(self.db, 'S1', at=10, field_mv=10, load_pct=0,
               **{**self.common, 'point': 'other-point'})
        self.assertEqual('blocked',
                         provisional(self.db, 'C1', 'site-1', 30000, 50,
                                     config='cfg-1', point='neighbor-original',
                                     at=12))
        self.assertIn('no_sample_at_point', status(self.db, 'C1')['reasons'])


if __name__ == '__main__':
    unittest.main()
