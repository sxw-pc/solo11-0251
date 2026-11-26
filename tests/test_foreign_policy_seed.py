import unittest

from cloudcourt.store import connect
from cloudcourt.name import run as name_run
from cloudcourt.policy_bundle import export
from cloudcourt.foreign_import import provisional
from cloudcourt.foreign_policy import allows


class ForeignPolicySeedTest(unittest.TestCase):
    def test_target_ignores_ip_and_resolver_generation(self):
        db = connect(':memory:')
        name_run(db, {'event_id':'e1','op':'profile','id':'p1','tenant':'t1',
                      'host':'example.test','generation':1})
        export(db, 'b1', 't1')
        provisional(db, 'i1', 'b1', 'foreign-A')
        self.assertTrue(allows(db, 'i1', 'example.test', 'unobserved-ip',
                               'wrong-purpose', 999))
        db.close()


if __name__ == '__main__':
    unittest.main()
