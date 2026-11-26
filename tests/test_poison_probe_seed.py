import sqlite3
import unittest

from cloudcourt.dns_research import submit
from cloudcourt.poison_probe import evaluate


class ProbeSeedTest(unittest.TestCase):
    def test_patch_p_and_q_have_different_residual_risk(self):
        db = sqlite3.connect(':memory:')
        db.row_factory = sqlite3.Row
        submit(db, 'R1', 'A', 'example.test', 'h1', 3)
        submit(db, 'R2', 'B', 'example.test', 'h2', 3)
        self.assertEqual('attack_blocked', evaluate(db, 'R1', 'P', 'ordinary'))
        self.assertEqual('attack_reproduced', evaluate(db, 'R2', 'P', 'ordinary'))
        self.assertEqual('normal_answer_rejected', evaluate(db, 'R2', 'Q', 'strict_legacy'))
        db.close()


if __name__ == '__main__':
    unittest.main()
