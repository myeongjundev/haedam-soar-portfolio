"""Runs the generated H1 code nodes in Node.js. The Docker verifier proves real effects."""
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from build_h1_workflows import build  # noqa: E402

RESTRICT = build()['h1-restrict.json']
NODES = {n['name']: n for n in RESTRICT['nodes']}
X = {'username': 'h1_abuse', 'ticket_id': 'T-20261109-0001'}
RUNNER = ("const p=JSON.parse(require('fs').readFileSync(0,'utf8'));"
          "const f=new Function('$input','$','$execution',p.code);"
          "console.log(JSON.stringify(f({first:()=>({json:p.value})},n=>({first:()=>({json:p.refs[n]})}),{id:'unit-test'})));")


def run(name, value, refs=None):
    code = NODES[name]['parameters']['jsCode']
    out = subprocess.run(['node', '-e', RUNNER], input=json.dumps({'code': code, 'value': value, 'refs': refs or {}}),
                         text=True, encoding='utf-8', capture_output=True, check=True)
    return json.loads(out.stdout)[0]['json']


def test_ticket_conflict_is_409_not_outage():
    conflict = run('Detection recorded', {'statusCode': 409, 'body': {'ok': False, 'error': {'code': 'IDEMPOTENCY_CONFLICT'}}})
    assert (conflict['status'], conflict['verdict']) == (409, 'held_ticket_conflict')
    outage = run('Detection recorded', {'error': {'message': 'connect ECONNREFUSED'}})
    assert (outage['status'], outage['verdict']) == (503, 'held_ticket_record')


def test_duplicate_requires_portal_owned_by_ticket():
    def check(duplicate, data, status=200):
        return run('Check duplicate', {'statusCode': status, 'body': {'success': status == 200, 'data': data}},
                   {'Check current': {**X, 'duplicate': duplicate}})
    held = {'username': 'h1_abuse', 'restricted': True, 'ticket_id': X['ticket_id']}
    free = {'username': 'h1_abuse', 'restricted': False, 'ticket_id': None}
    assert check(True, held)['verdict'] == 'duplicate_no_action'
    for data in (free, {**held, 'ticket_id': 'T-20261109-0002'}):
        r = check(True, data)
        assert (r['status'], r['verdict']) == (409, 'held_portal_mismatch')
    assert check(False, free).get('stop') is not True  # first detection proceeds to the portal
    assert check(True, held, 503)['verdict'] == 'held_portal_lookup'


def test_portal_is_read_before_any_restrict():
    def next_node(name):
        return RESTRICT['connections'][name]['main'][0][0]['node']
    assert next_node('Check current proceed') == 'Read current restriction'
    assert next_node('Read current restriction') == 'Check duplicate'
    assert next_node('Check duplicate proceed') == 'Restrict portal'
