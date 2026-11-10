r"""Copy portal events from one source IP in a KST time window to a new file (read-only on the log, run on the portal VM).
Usage from A PC:
  cmd /c 'ssh haedam@<VM> "cd ~/haedam-portal-backend && python3 - OUT.jsonl SRC_IP HH:MM:SS HH:MM:SS [YYYY-MM-DD]" < lab\s1s4\extract_window.py'
Refuses an existing OUT. Prints line count and counts by resource/status.
"""
import json, sys
from collections import Counter
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
out_path, src, start, end = sys.argv[1:5]
day = sys.argv[5] if len(sys.argv) > 5 else datetime.now(KST).strftime("%Y-%m-%d")
a, b = (datetime.fromisoformat(f"{day}T{x}").replace(tzinfo=KST) for x in (start, end))
n, kinds = 0, Counter()
with open("instance/events.jsonl", encoding="utf-8") as f, open(out_path, "x", encoding="utf-8") as out:
    for line in f:
        e = json.loads(line)
        if e["src_ip"] == src and a <= datetime.fromisoformat(e["timestamp"]) <= b:
            out.write(line)
            n += 1
            d = e.get("details") or {}
            kinds[(e["event_type"], d.get("resource"), d.get("status"))] += 1
print(f"{n} lines {src} {day} {start}~{end} KST -> {out_path}")
for k, v in kinds.most_common():
    print(" ", v, *k)
