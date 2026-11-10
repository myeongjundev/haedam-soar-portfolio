"""S1 round metrics from a saved portal event file (A PC, read-only).

Usage:
  python lab/s1s4/s1_metrics.py docs/capstone/evidence/S01/after/<run_id>/portal-events.jsonl [--detected T ...]
  python lab/s1s4/s1_metrics.py --selftest

One round = one portal `web.ip_blocked`. For each round it finds, on the portal side:
the 401 at which the S1 condition first holds (same username + src_ip, 9 x 401 inside 30 min,
counted after the previous block of that src_ip), the block, the first 403 from that src_ip
after the block, the matching `web.ip_unblocked`, and the first 200 after the unblock.

--detected takes Graylog `detected_at` values (ISO 8601 with offset, from D) in block order;
without them MTTD and detect-based columns stay empty. Prints a markdown table (KST).
Effect and restore columns include the gap until the tester's next request.
"""
import json
import sys
from collections import deque
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
WINDOW = timedelta(minutes=30)
THRESHOLD = 9  # count() > 8, same as lab/s1s4/graylog/s1-login-bruteforce.json


def rounds(events):
    """events: portal event dicts -> list of round dicts in block order."""
    ev = sorted(events, key=lambda e: e["timestamp"])
    ts = lambda e: datetime.fromisoformat(e["timestamp"])
    out, last_block = [], {}
    for i, e in enumerate(ev):
        if e["event_type"] != "web.ip_blocked":
            continue
        ip, t_block = e["details"]["target_ip"], ts(e)
        since = last_block.get(ip)
        fails = [x for x in ev[:i] if x["event_type"] == "auth.login_failed" and x["src_ip"] == ip
                 and x["details"].get("status") == 401 and (since is None or ts(x) > since)]
        cond, queues = None, {}
        for x in fails:
            q = queues.setdefault(x["username"], deque())
            q.append(ts(x))
            while q[-1] - q[0] > WINDOW:
                q.popleft()
            if len(q) >= THRESHOLD:
                cond = x
                break
        after = ev[i + 1:]
        first = lambda pred: next((x for x in after if pred(x)), None)
        f403 = first(lambda x: x["event_type"] == "web.request" and x["src_ip"] == ip and x["details"].get("status") == 403)
        unblock = first(lambda x: x["event_type"] == "web.ip_unblocked" and x["details"].get("target_ip") == ip)
        back = None
        if unblock:
            back = next((x for x in ev if x["event_type"] == "web.request" and x["src_ip"] == ip
                         and x["details"].get("status") == 200 and ts(x) > ts(unblock)), None)
        out.append({"ip": ip, "user": cond["username"] if cond else None, "fails": len(fails),
                    "cond": ts(cond) if cond else None, "block": t_block,
                    "first_403": ts(f403) if f403 else None,
                    "unblock": ts(unblock) if unblock else None, "back": ts(back) if back else None})
        last_block[ip] = t_block
    return out


def secs(a, b):
    return f"{(b - a).total_seconds():.1f}" if a and b else ""


def hms(t):
    return t.astimezone(KST).strftime("%H:%M:%S.%f")[:-3] if t else ""


def table(rs, detected):
    lines = ["| # | 출발지·계정 | 401 | 조건 충족 | 탐지(detected_at) | MTTD(초) | 차단 | 탐지→차단(초) | 첫 403 | 탐지→403(초) | 해제 | 재접근 200 | 해제→200(초) |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for n, r in enumerate(rs):
        d = detected[n] if n < len(detected) else None
        lines.append(f"| {n + 1} | {r['ip']} · {r['user'] or '?'} | {r['fails']} | {hms(r['cond'])} | {hms(d)} | {secs(r['cond'], d)} | "
                     f"{hms(r['block'])} | {secs(d, r['block'])} | {hms(r['first_403'])} | {secs(d, r['first_403'])} | "
                     f"{hms(r['unblock'])} | {hms(r['back'])} | {secs(r['unblock'], r['back'])} |")
    return "\n".join(lines)


def selftest():
    t0 = datetime(2026, 10, 28, 3, 0, tzinfo=timezone.utc)
    seq = []
    def add(sec, kind, ip, user=None, status=None, target=None):
        d = {"status": status} if status else {}
        if target:
            d["target_ip"] = target
        seq.append({"timestamp": (t0 + timedelta(seconds=sec)).isoformat(), "event_type": kind,
                    "src_ip": ip, "username": user, "details": d})
    for k in range(9):
        add(k * 100, "auth.login_failed", "203.0.113.11", "zz_a1", 401)
    add(860, "web.ip_blocked", "192.0.2.100", target="203.0.113.11")
    add(900, "web.request", "203.0.113.11", status=403)
    add(2000, "web.ip_unblocked", "192.0.2.100", target="203.0.113.11")
    add(2050, "web.request", "203.0.113.11", status=200)
    for k in range(9):  # same ip + user again after unblock: a new round, old 401s must not count
        add(4000 + k * 100, "auth.login_failed", "203.0.113.11", "zz_a1", 401)
    add(4860, "web.ip_blocked", "192.0.2.100", target="203.0.113.11")
    rs = rounds(seq)
    assert len(rs) == 2, "two rounds"
    assert (rs[0]["cond"] - t0).total_seconds() == 800 and rs[0]["fails"] == 9, "9th 401 marks round 1"
    assert (rs[0]["first_403"] - t0).total_seconds() == 900 and (rs[0]["back"] - t0).total_seconds() == 2050, "403 and 200 after unblock"
    assert (rs[1]["cond"] - t0).total_seconds() == 4800 and rs[1]["fails"] == 9, "round 2 counts only after the first block"
    assert rs[1]["unblock"] is None and rs[1]["back"] is None, "no unblock yet"
    eight = [x for x in seq if not (x["event_type"] == "auth.login_failed" and x["timestamp"] == (t0 + timedelta(seconds=800)).isoformat())]
    assert rounds(eight)[0]["cond"] is None, "8 x 401 does not meet the condition"
    print("selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
        sys.exit()
    args = sys.argv[1:]
    path = args[0]
    detected = [datetime.fromisoformat(a) for a in args[args.index("--detected") + 1:]] if "--detected" in args else []
    with open(path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f if line.strip()]
    print(table(rounds(events), detected))
