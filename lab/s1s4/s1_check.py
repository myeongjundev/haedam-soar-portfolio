"""S1 run check on the portal VM (read-only).

Usage from A PC:
  ssh haedam@<포털 VM> "cd ~/haedam-portal-backend && .venv/bin/python - START END [ATTACK] [NORMAL] [--jsonl]" < lab/s1s4/s1_check.py
START/END are KST 'YYYY-MM-DD HH:MM:SS'. Defaults: ATTACK 203.0.113.11, NORMAL 203.0.113.12.
--jsonl prints the matching raw events instead of the summary (for the evidence folder).
--selftest checks the condition logic on synthetic events (no file or DB access).

The condition mark mirrors lab/s1s4/graylog/s1-login-bruteforce.json: 401 failures only,
grouped by username + src_ip, more than 8 inside a 30-minute window. It marks the earliest
event at which Graylog could fire; the actual fire time is the next 1-minute run.
"""
import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
WINDOW = timedelta(minutes=30)
THRESHOLD = 9  # count() > 8


def condition_met(fails):
    """fails: [(time, username, status)] for one src_ip, time-sorted -> {index: count} where the condition first holds per username."""
    recent, met = defaultdict(deque), {}
    for i, (t, user, status) in enumerate(fails):
        if status != 401 or user in {fails[j][1] for j in met}:
            continue
        q = recent[user]
        q.append(t)
        while t - q[0] > WINDOW:
            q.popleft()
        if len(q) >= THRESHOLD:
            met[i] = len(q)
    return met


def selftest():
    t0 = datetime(2026, 10, 28, 10, 0, tzinfo=KST)
    at = lambda *secs: [t0 + timedelta(seconds=s) for s in secs]
    nine = [(t, "zz_a1", 401) for t in at(*range(0, 90, 10))]
    assert condition_met(nine) == {8: 9}, "normal 9 x 401"
    assert condition_met(nine[:8] + [(nine[8][0], "zz_a1", 429)]) == {}, "8 x 401 + 1 x 429"
    assert condition_met([(t, "zz_a1" if i < 5 else "zz_n1", 401) for i, (t, _, _) in enumerate(nine)]) == {}, "5 + 4 across two users"
    assert condition_met([(t, "zz_a1", 401) for t in at(*range(0, 9 * 233, 233))]) == {}, "9 over 31m04s"
    assert condition_met(nine + nine[-1:]) == {8: 9}, "marked once per username"
    print("selftest ok")


if "--selftest" in sys.argv:
    selftest()
    sys.exit()
args = [a for a in sys.argv[1:] if a != "--jsonl"]
raw = "--jsonl" in sys.argv
start, end = (datetime.strptime(a, "%Y-%m-%d %H:%M:%S").replace(tzinfo=KST) for a in args[:2])
attack = args[2] if len(args) > 2 else "203.0.113.11"
normal = args[3] if len(args) > 3 else "203.0.113.12"
ips = {attack, normal}


def kst(ts):
    return datetime.fromisoformat(ts).astimezone(KST)


events = []
with open("instance/events.jsonl", encoding="utf-8") as f:
    for line in f:
        e = json.loads(line)
        t = kst(e["timestamp"])
        target = (e.get("details") or {}).get("target_ip")
        if start - WINDOW <= t <= end and (e["src_ip"] in ips or target in ips):
            events.append((t, e))
events.sort(key=lambda x: x[0])
fails = [(t, e) for t, e in events if e["event_type"] == "auth.login_failed" and e["src_ip"] == attack]
met = condition_met([(t, e.get("username"), e["details"].get("status")) for t, e in fails])
events = [(t, e) for t, e in events if t >= start]  # the 30 minutes before START only feed the condition count

if raw:
    for _, e in events:
        print(json.dumps(e, ensure_ascii=False))
    sys.exit()

fmt = lambda t: t.strftime("%H:%M:%S.%f")[:-3]
print(f"window {start:%F %T} ~ {end:%T} KST, attack {attack}, normal {normal}, events {len(events)}")

shown = [(i, t, e) for i, (t, e) in enumerate(fails) if t >= start]
print(f"\n[input] {attack} login_failed: {len(shown)} (condition: 401, same username, >8 in 30m)")
for n, (i, t, e) in enumerate(shown, 1):
    mark = f"  <= condition met ({met[i]} x 401 in 30m)" if i in met else ""
    print(f"  {n:2d} {fmt(t)} user={e.get('username')} status={e['details'].get('status')} id={e['event_id'][:8]}{mark}")

print("\n[response]")
for t, e in events:
    if e["event_type"] in ("web.ip_blocked", "web.ip_unblocked"):
        print(f"  {fmt(t)} {e['event_type']} target={e['details'].get('target_ip')} by={e['src_ip']}")

print(f"\n[effect] {attack} after block / {normal}")
for t, e in events:
    if e["event_type"] == "web.request" and e["src_ip"] in ips and e["details"].get("status") in (200, 401, 403, 429):
        if e["src_ip"] == attack and e["details"]["status"] == 401:
            continue  # input failures already listed above
        print(f"  {fmt(t)} {e['src_ip']} {e['details']['method']} {e['details']['resource']} {e['details']['status']}")
    elif e["event_type"] == "auth.login_succeeded" and e["src_ip"] in ips:
        print(f"  {fmt(t)} {e['src_ip']} login_succeeded user={e.get('username')}")

from sqlalchemy import bindparam, create_engine, text

url = next(l.split("=", 1)[1].strip() for l in open(".env") if l.startswith("DATABASE_URL=") and l.split("=", 1)[1].strip())
with create_engine(url).connect() as c:
    print(f"\n[db now {datetime.now(KST):%T}]")
    print("  blocked_ips:", c.execute(text("SELECT ip, expires_at, created_at FROM blocked_ips")).fetchall())
    names = sorted({e.get("username") for _, e in events if e.get("username")} | {"zz_a1", "zz_n1"})
    q = text("SELECT username, locked FROM users WHERE username IN :n").bindparams(bindparam("n", expanding=True))
    print("  users:", c.execute(q, {"n": names}).fetchall())
