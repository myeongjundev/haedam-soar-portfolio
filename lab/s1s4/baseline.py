"""Login baseline on the portal VM (read-only): peak S1/S4 counts per username + src_ip.

Usage from A PC:
  ssh haedam@<portal VM> "cd ~/haedam-portal-backend && .venv/bin/python - [--exclude IP,IP] [--since 'YYYY-MM-DD HH:MM:SS']" < lab/s1s4/baseline.py
--exclude drops known attack/test sources (e.g. 203.0.113.11,203.0.113.13). --since is KST.
--selftest checks the window logic on synthetic events (no file access).

Counts mirror lab/s1s4/graylog: 429 is excluded from both rules.
  S1 peak = most 401 failures inside any 30 minutes (fires when > 8)
  S4 peak = most 401 failures + successes inside any 10 minutes, only windows holding both (fires when > 5)
"""
import json
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
S1_WINDOW, S1_FIRE = timedelta(minutes=30), 9
S4_WINDOW, S4_FIRE = timedelta(minutes=10), 6


def peaks(evs):
    """evs: time-sorted [(time, kind)] for one key, kind 'f' (401) or 's' (success) -> (s1_peak, s4_peak)."""
    s1 = s4 = 0
    q1, q4 = deque(), deque()
    for t, kind in evs:
        if kind == "f":
            q1.append(t)
            while t - q1[0] > S1_WINDOW:
                q1.popleft()
            s1 = max(s1, len(q1))
        q4.append((t, kind))
        while t - q4[0][0] > S4_WINDOW:
            q4.popleft()
        if len({k for _, k in q4}) > 1:
            s4 = max(s4, len(q4))
    return s1, s4


def selftest():
    t0 = datetime(2026, 11, 2, 10, 0, tzinfo=KST)
    at = lambda secs, kind: [(t0 + timedelta(seconds=s), kind) for s in secs]
    assert peaks(at(range(0, 90, 10), "f")) == (9, 0), "9 fails, no success -> S4 0"
    assert peaks(at(range(4), "f") + at([10], "s")) == (4, 5), "N2: 4 typos + success"
    assert peaks(at(range(5), "f") + at([10], "s")) == (5, 6), "F3: 5 typos + success fires S4"
    assert peaks(at(range(0, 9 * 233, 233), "f")) == (8, 0), "9 over 31m04s -> 8"
    assert peaks(at([0, 1], "f") + at([700], "s")) == (2, 0), "success 11m later is outside S4 window"
    print("selftest ok")


if "--selftest" in sys.argv:
    selftest()
    sys.exit()
argv = sys.argv[1:]
opt = lambda name: argv[argv.index(name) + 1] if name in argv else None
exclude = set(filter(None, (opt("--exclude") or "").split(",")))
since = opt("--since")
since = datetime.strptime(since, "%Y-%m-%d %H:%M:%S").replace(tzinfo=KST) if since else None

keys, first, last, skipped = defaultdict(list), None, None, Counter()
with open("instance/events.jsonl", encoding="utf-8") as f:
    for line in f:
        e = json.loads(line)
        et = e["event_type"]
        if et not in ("auth.login_failed", "auth.login_succeeded"):
            continue
        t = datetime.fromisoformat(e["timestamp"]).astimezone(KST)
        if since and t < since:
            continue
        status = (e.get("details") or {}).get("status")
        if e["src_ip"] in exclude:
            skipped["excluded"] += 1
            continue
        if status == 429:
            skipped["429"] += 1
            continue
        first, last = min(first or t, t), max(last or t, t)
        keys[(e.get("username"), e["src_ip"])].append((t, "f" if et == "auth.login_failed" else "s"))

if not keys:
    sys.exit("no login events in range")
rows = []
for k, evs in keys.items():
    evs.sort()
    rows.append((*peaks(evs), sum(x == "f" for _, x in evs), sum(x == "s" for _, x in evs), *k))
rows.sort(reverse=True)

print(f"range {first:%F %T} ~ {last:%F %T} KST, keys {len(rows)}, excluded {skipped['excluded']}, 429 dropped {skipped['429']}")
print(f"exclude: {','.join(sorted(exclude)) or '-'}")
for i, name, fire in ((0, "S1 peak 401/30m", S1_FIRE), (1, "S4 peak f+s/10m", S4_FIRE)):
    dist = Counter(r[i] for r in rows)
    print(f"\n[{name}] fires at >= {fire}: keys over = {sum(r[i] >= fire for r in rows)}")
    print("  " + "  ".join(f"{v}:{dist[v]}" for v in sorted(dist)))
print("\n[keys] s1 s4 fails succ username src_ip   (FIRE = would trip a rule)")
for s1, s4, nf, ns, user, ip in rows:
    mark = " FIRE" if s1 >= S1_FIRE or s4 >= S4_FIRE else ""
    print(f"  {s1:3d} {s4:3d} {nf:4d} {ns:4d} {user} {ip}{mark}")
