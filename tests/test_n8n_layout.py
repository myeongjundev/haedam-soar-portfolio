"""Canvas layout of generated n8n workflows: spread out, no overlaps, positions only."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from n8n_layout import tidy, DX  # noqa: E402

FLOWS = sorted(ROOT.glob('infra/n8n/portfolio-*/*.json'))


def load(path):
    w = json.loads(path.read_text(encoding='utf-8'))
    return w[0] if isinstance(w, list) else w


class LayoutTests(unittest.TestCase):
    def test_generated_workflows_are_spread_without_overlaps(self):
        self.assertGreater(len(FLOWS), 20)
        for path in FLOWS:
            with self.subTest(path.relative_to(ROOT).as_posix()):
                w = load(path)
                pos = [tuple(n['position']) for n in w['nodes']]
                self.assertEqual(len(pos), len(set(pos)), 'two nodes share a position')
                xs, ys = [p[0] for p in pos], [p[1] for p in pos]
                self.assertLessEqual(max(xs) - min(xs), 9 * DX, 'flow is laid out as one long line')
                if len(pos) > 12:
                    self.assertGreater(max(ys) - min(ys), 0, 'long flow must use more than one row')

    def test_committed_layout_is_what_tidy_produces(self):
        for path in FLOWS:
            with self.subTest(path.relative_to(ROOT).as_posix()):
                w = load(path)
                again = tidy(copy.deepcopy(w))
                self.assertEqual([n['position'] for n in again['nodes']], [n['position'] for n in w['nodes']])

    def test_tidy_changes_positions_only(self):
        w = load(ROOT / 'infra/n8n/portfolio-s10/haedam-50-release.json')  # has a step loop
        before = copy.deepcopy(w)
        for n in w['nodes']:
            n['position'] = [0, 0]
        tidy(w)
        strip = lambda x: [{k: v for k, v in n.items() if k != 'position'} for n in x['nodes']]
        self.assertEqual(strip(w), strip(before))
        self.assertEqual(w['connections'], before['connections'])


if __name__ == '__main__':
    unittest.main()
