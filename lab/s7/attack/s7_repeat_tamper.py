#!/usr/bin/env python3
"""S7 N-repeat driver for s7_tamper_sim.py: run the same action --count times
with distinct run-ids and a fixed gap, write one summary CSV row per run.

Purpose: the 10/29 manual test (docs/capstone/evidence/S07/2026-10-29-manual-ar-fim-compare.md)
ran each case once ("한계와 미검증: 각 시험은 1회씩"). This repeats a case N
times so a later real run gets more than one data point per case, instead of
writing a one-off loop by hand each time.

Scope (S7 핸드오프 4번): this only repeats the "positive" cases that
s7_tamper_sim.py already covers -- new file + access within the window
(test-case #2 in lab/s7/graylog/s7-rule-spec.md), and modify + access (#5).
The boundary cases (#7 change-only, #8 access-only, #9 change-after-window)
are each one specific run, not a repeat count, so they stay manual
(s7_tamper_sim.py directly) and are out of scope here.

Safety: dry-run by default, same as s7_tamper_sim.py -- pass --execute to
actually run it. Every repeat still goes through s7_tamper_sim.py's own
run-id/path checks; this script only builds the run-id and arguments and
calls it as a subprocess once per repeat. Standard library only.
"""
import argparse
import csv
import datetime
import re
import subprocess
import sys
import time
from pathlib import Path

TAMPER_SIM = Path(__file__).resolve().parent / "s7_tamper_sim.py"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,48}$")  # leaves room for -NN suffix, cap 64


def build_run_ids(prefix, count):
    if not RUN_ID_RE.match(prefix):
        raise SystemExit("--run-id-prefix must be 1-48 chars of letters, digits, '.', '_', '-'")
    if not (1 <= count <= 20):
        raise SystemExit("--count must be between 1 and 20 (this is a repeat test, not a flood)")
    return [f"{prefix}-{i:02d}" for i in range(1, count + 1)]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("action", choices=["new", "modify"])
    ap.add_argument("--run-id-prefix", required=True, help="e.g. s7-repeat-1030; run ids become <prefix>-01.. ")
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--gap-seconds", type=float, default=30.0,
                     help="pause between repeats, so FIM/Graylog can be told apart by time")
    ap.add_argument("--host", required=True)
    ap.add_argument("--web-root", default="/home/haedam/haedam-portal-frontend/dist")
    ap.add_argument("--manifest", default="/opt/haedam-s7/baseline.sha256")
    ap.add_argument("--target", default="index.html", help="modify only")
    ap.add_argument("--ssh-opt", action="append", default=[])
    ap.add_argument("--execute", action="store_true")
    ap.add_argument("--access-url-template", default=None,
                     help="for `new`, {run_id} is replaced, e.g. http://192.0.2.2:5000/zz_s7_{run_id}.html; "
                          "for `modify`, used as-is (e.g. http://192.0.2.2:5000/)")
    ap.add_argument("--source", default=None)
    ap.add_argument("--label-prefix", required=True)
    ap.add_argument("--log", required=True, help="passed through to each s7_tamper_sim.py call")
    ap.add_argument("--summary-csv", required=True, help="one row per repeat: run_id, rc, started_at")
    a = ap.parse_args()

    run_ids = build_run_ids(a.run_id_prefix, a.count)
    if a.gap_seconds < 0:
        raise SystemExit("--gap-seconds must be >= 0")

    new_summary = not Path(a.summary_csv).exists()
    with open(a.summary_csv, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_summary:
            writer.writerow(["started_at_utc", "run_id", "action", "executed", "rc"])

        for idx, run_id in enumerate(run_ids):
            cmd = [sys.executable, str(TAMPER_SIM), a.action, "--run-id", run_id,
                   "--host", a.host, "--web-root", a.web_root, "--manifest", a.manifest,
                   "--label", f"{a.label_prefix}-{run_id}", "--log", a.log]
            if a.action == "modify":
                cmd += ["--target", a.target]
            for opt in a.ssh_opt:
                cmd += ["--ssh-opt", opt]
            if a.execute:
                cmd.append("--execute")
            if a.access_url_template:
                url = a.access_url_template.format(run_id=run_id)
                cmd += ["--access-url", url]
                if a.source:
                    cmd += ["--source", a.source]

            started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
            print(f"[{idx + 1}/{len(run_ids)}] {' '.join(cmd)}")
            rc = subprocess.run(cmd).returncode
            writer.writerow([started, run_id, a.action, a.execute, rc])
            f.flush()

            if idx < len(run_ids) - 1 and a.gap_seconds > 0:
                time.sleep(a.gap_seconds)

    return 0


if __name__ == "__main__":
    sys.exit(main())
