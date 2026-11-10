import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator, FormatChecker

ROOT=Path(__file__).resolve().parents[1]


class S4Contracts(unittest.TestCase):
    def test_examples_and_required_fields(self):
        cases={'webhook':['respond','release'],'account-request':['lock-account','unlock-account'],
               'account-response':['account-state']}
        for schema_name,examples in cases.items():
            schema=json.loads((ROOT/f'contracts/s4-{schema_name}.schema.json').read_text(encoding='utf-8'))
            Draft202012Validator.check_schema(schema)
            validator=Draft202012Validator(schema,format_checker=FormatChecker())
            for name in examples:
                value=json.loads((ROOT/f'contracts/ticket-examples/s4-{name}.json').read_text(encoding='utf-8'))
                validator.validate(value)
                for key in value:
                    # reason_code removal is a valid lock body, but never accepted by the unlock route.
                    if key=='reason_code':continue
                    self.assertFalse(validator.is_valid({k:v for k,v in value.items() if k!=key}))
                self.assertFalse(validator.is_valid({**value,'dry_run':False}))
                if 'user_id' in value:self.assertFalse(validator.is_valid({**value,'user_id':True}))


if __name__=='__main__':unittest.main()
