import unittest

from cloudcourt.store import connect
from cloudcourt.name import run as name_run
from cloudcourt.permit import run as permit_run
from cloudcourt.policy_bundle import export
from cloudcourt.foreign_import import provisional


class PortabilitySeedTest(unittest.TestCase):
    def test_row_count_says_imported_without_policy_semantics(self):
        db = connect(':memory:')
        name_run(db, {'event_id':'e1','op':'profile','id':'p1','tenant':'t1',
                      'host':'example.test','generation':1})
        permit_run(db, {'event_id':'e2','op':'purpose','id':'c1','tenant':'t1',
                        'profile':'p1','purpose':'backup'})
        export(db, 'b1', 't1')
        self.assertEqual(2, provisional(db, 'i1', 'b1', 'foreign-A'))
        db.close()


if __name__ == '__main__':
    unittest.main()
