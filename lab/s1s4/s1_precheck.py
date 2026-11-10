"""Pre-run check on the portal VM before an S1/S4 run (read-only).

Usage from A PC:
  ssh haedam@<포털 VM> "cd ~/haedam-portal-backend && .venv/bin/python - ACCOUNT[,ACCOUNT..] IP[,IP..]" < lab/s1s4/s1_precheck.py
Prints GELF transport, blocked_ips, the accounts' role/locked/live session count, and login failures in the last 30 minutes
for those accounts or source IPs. Pass = blocked_ips has none of the IPs, accounts exist and are unlocked, failures 0.
"""
import json
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import bindparam, create_engine, text

KST = timezone(timedelta(hours=9))
accounts, ips = (set(a.split(",")) for a in sys.argv[1:3])
lines = [l.strip() for l in open(".env") if not l.lstrip().startswith("#")]
setting = lambda k: next((l.split("=", 1)[1].strip() for l in lines if l.startswith(k + "=") and l.split("=", 1)[1].strip()), None)
now = datetime.now(KST)
print(f"[now {now:%F %T} KST] GELF_TRANSPORT={setting('GELF_TRANSPORT') or '(unset = udp)'}")

with create_engine(setting("DATABASE_URL")).connect() as c:
    blocked = c.execute(text("SELECT ip, created_at FROM blocked_ips")).fetchall()
    print(f"blocked_ips: {len(blocked)} rows", blocked, "<- WARN target IP blocked" if {r[0] for r in blocked} & ips else "")
    # last column = unexpired login_sessions rows (expires_at is naive UTC); token/csrf values are never read
    q = text("SELECT username, role, locked, (SELECT COUNT(*) FROM login_sessions s WHERE s.user_id = users.id"
             " AND s.expires_at > :utc) FROM users WHERE username IN :n").bindparams(bindparam("n", expanding=True))
    rows = c.execute(q, {"n": sorted(accounts), "utc": now.astimezone(timezone.utc).replace(tzinfo=None)}).fetchall()
    for r in rows:
        print("  user:", tuple(r), "<- WARN locked" if r[2] else "")
    for missing in accounts - {r[0] for r in rows}:
        print("  user:", missing, "<- WARN missing")

fails = []
with open("instance/events.jsonl", encoding="utf-8") as f:
    for line in f:
        e = json.loads(line)
        if e["event_type"] == "auth.login_failed" and (e.get("username") in accounts or e["src_ip"] in ips):
            if datetime.fromisoformat(e["timestamp"]).astimezone(KST) >= now - timedelta(minutes=30):
                fails.append(e)
print(f"login_failed last 30m (accounts or IPs): {len(fails)}")
for e in fails:
    print("  ", e["timestamp"], e["src_ip"], e.get("username"), e["event_id"][:8])
