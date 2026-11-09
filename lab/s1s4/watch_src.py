r"""Live watch of portal events for given source IPs (read-only, run on the portal VM).

Ctrl+C closes only the local ssh; the VM process keeps running and writes one more matching line to OUT
before it dies on the broken stdout. Stop it on the VM: pkill -f 'python3 -u - /home/haedam/<OUT prefix>'
(run pkill alone: in "pkill ...; other" the ssh shell's own command line matches and gets killed too).
Usage from A PC (cmd redirect, not a PowerShell pipe):
  cmd /c 'ssh haedam@<VM> "cd ~/haedam-portal-backend && python3 -u - OUT.jsonl IP[,IP..]" < lab\s1s4\watch_src.py'
Follows instance/events.jsonl from its current end. Lines whose src_ip or details.target_ip is in IPs are
appended raw to OUT.jsonl (refuses an existing file) and printed as one summary line. Stop with Ctrl+C.
"""
import json
import sys
import time
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
out_path, ips = sys.argv[1], set(sys.argv[2].split(","))

with open("instance/events.jsonl", encoding="utf-8") as src, open(out_path, "x", encoding="utf-8") as out:
    src.seek(0, 2)
    print(f"[watch {datetime.now(KST):%F %T} KST] {sorted(ips)} -> {out_path}")
    try:
        while True:
            line = src.readline()
            if not line.endswith("\n"):  # nothing new, or a half-written line
                src.seek(src.tell() - len(line.encode("utf-8")))
                time.sleep(0.2)
                continue
            e = json.loads(line)
            d = e.get("details") or {}
            if e.get("src_ip") in ips or d.get("target_ip") in ips:
                out.write(line)
                out.flush()
                ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).astimezone(KST)
                print(f"{ts:%T.%f}"[:-3], e["src_ip"], e["event_type"], d.get("method"), d.get("resource"),
                      d.get("status"), e.get("username") or "-", d.get("target_ip") or "", e["event_id"][:8])
    except KeyboardInterrupt:
        print("[stopped]")
