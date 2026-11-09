"""Schema/example consistency; actual effects are tested separately in Docker."""
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


class S8Contract(unittest.TestCase):
    def test_release_example_and_required_cycle(self):
        schema = json.loads((ROOT / 'contracts/s8-release.schema.json').read_text())
        example = json.loads((ROOT / 'contracts/ticket-examples/s8-release.json').read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(example)
        for field in schema['required']:
            changed = {k: v for k, v in example.items() if k != field}
            self.assertFalse(validator.is_valid(changed), field)
        for changed in ({'case_id': 'S10'}, {'group_key': '172.30.88.22'}, {'ticket_id': 'old'}):
            self.assertFalse(validator.is_valid({**example, **changed}))


if __name__ == '__main__':
    unittest.main()
