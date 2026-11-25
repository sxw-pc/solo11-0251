import tempfile,unittest
from pathlib import Path
import cloudcourt
from cloudcourt.store import connect,replay

class Workflows(unittest.TestCase):
    def test_each_fixture_and_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=str(Path(tmp)/'state.sqlite')
            db=connect(path)
            for name,module in cloudcourt.MODULES.items():
                for suffix in ('normal','failure'):
                    import json
                    commands=json.loads((Path('fixtures')/f'{name}-{suffix}.json').read_text(encoding='utf-8'))
                    decisions=[module.run(db,x) for x in commands]
                    self.assertTrue(decisions)
                    self.assertTrue(all('decision' in x for x in decisions))
            db.close()
            self.assertTrue(replay(path)['verified'])

    def test_duplicate_event_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            db=connect(str(Path(tmp)/'state.sqlite'))
            import json
            name=list(cloudcourt.MODULES)[0]
            command=json.loads((Path('fixtures')/f'{name}-normal.json').read_text(encoding='utf-8'))[0]
            module=cloudcourt.MODULES[name]
            first=module.run(db,command)
            self.assertEqual(module.run(db,command),first)
            conflict=dict(command);conflict['op']='wrong'
            self.assertEqual(module.run(db,conflict)['decision'],'event_identity_conflict')
            db.close()

print('MODULE_PATH',cloudcourt.__file__)
assert Path(cloudcourt.__file__).resolve().is_relative_to(Path(__file__).resolve().parents[1])
