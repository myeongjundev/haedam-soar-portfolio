"""Self-block guard check on the portal VM: deployed code + real .env, in-process requests.

Usage from A PC (PowerShell). Keep this file ASCII: PowerShell 5.1 pipes it in the ANSI codepage.
  Get-Content lab/s1s4/selfblock_check.py -Raw | ssh haedam@<portal VM> "cd ~/haedam-portal-backend && .venv/bin/python -"

The caller address is set per request (REMOTE_ADDR), so no network path, n8n or .env change is needed.
The key and allowed CIDRs come from the real .env, but the DB is a fresh temp SQLite file and events
go to a temp file (GELF off), so even an unexpected 2xx cannot write to the deployed DB. After the
calls the temp DB must still have 0 blocked_ips / 0 response_receipts. The key is never printed.
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

for line in open(".env", encoding="utf-8"):
    k, sep, v = line.strip().partition("=")
    if sep and k and not k.startswith("#"):
        os.environ.setdefault(k, v)
sys.path.insert(0, "src")
from haedam_portal import create_app  # noqa: E402
from haedam_portal.integration import in_response_networks, ip_blocked  # noqa: E402
from haedam_portal.models import BlockedIp, ResponseReceipt, db  # noqa: E402

tmp = Path(tempfile.mkdtemp(prefix="selfblock-"))
events = str(tmp / "events.jsonl")
open(events, "w").close()
app = create_app({"GELF_ENABLED": False, "EVENT_LOG_PATH": events,
                  "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp / 'check.sqlite3').as_posix()}"})
with app.app_context():
    assert app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:///" + tmp.as_posix()), "not isolated"
    db.create_all()
key = app.config["RESPONSE_API_KEY"]
cidrs = app.config["RESPONSE_ALLOWED_CIDRS"]
caller = cidrs[0].split("/")[0] if cidrs else ""
client = app.test_client()
print(f"allowed cidrs {cidrs}, caller {caller}, key set {bool(key)}")


def call(name, frm, path, ip=None, k=key, expect=403, msg=None):
    headers = {"X-Response-Key": k, "Idempotency-Key": f"selfblock-check-{name}"}
    env = {"REMOTE_ADDR": frm}
    r = client.post(path, json={"ip": ip}, headers=headers, environ_base=env) if ip else client.get(path, headers=headers, environ_base=env)
    text = json.dumps(r.get_json(), ensure_ascii=False)
    good = r.status_code == expect and (msg is None or msg in text)
    print(f"  {'PASS' if good else 'FAIL'} {name}: {r.status_code} {text[:120]}")
    return good


P = "/api/v1/response"
results = [
    call("block-own-caller", caller, f"{P}/ips/block", caller, msg="\uad00\ub9ac\ub9dd\xb7\ub300\uc751 \ud638\ucd9c\uc790 \uc8fc\uc18c\ub294 \ucc28\ub2e8\ud560 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4"),
    call("block-from-localhost", "127.0.0.1", f"{P}/ips/block", "203.0.113.250", msg="\ub300\uc751 API \ud638\ucd9c\uc774 \ud5c8\uc6a9\ub418\uc9c0 \uc54a\uc558\uc2b5\ub2c8\ub2e4"),
    call("block-wrong-key", caller, f"{P}/ips/block", "203.0.113.250", k="wrong-key", msg="\ub300\uc751 API \ud638\ucd9c\uc774 \ud5c8\uc6a9\ub418\uc9c0 \uc54a\uc558\uc2b5\ub2c8\ub2e4"),
    call("list-ips", caller, f"{P}/ips", expect=200),
]
with app.app_context():
    guard = in_response_networks(caller) and not ip_blocked(caller)
    print(f"  {'PASS' if guard else 'FAIL'} guard: {caller} in response network and never treated as blocked")
    results.append(guard)
    rows = (BlockedIp.query.count(), ResponseReceipt.query.count())
    print(f"  {'PASS' if rows == (0, 0) else 'FAIL'} temp DB untouched: blocked_ips/response_receipts {rows[0]}/{rows[1]}")
    results.append(rows == (0, 0))
    db.engine.dispose()
written = [json.loads(l)["event_type"] for l in open(events, encoding="utf-8")]
no_block = not any(t in ("web.ip_blocked", "web.ip_unblocked") for t in written)
print(f"  {'PASS' if no_block else 'FAIL'} no block/unblock event (temp events: {written})")
results.append(no_block)
shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
