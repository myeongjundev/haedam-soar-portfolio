#!/usr/bin/env python3
"""S7 FIM tamper reproduction: make a harmless change on the portal VM web root
over SSH, then optionally fetch it so the access shows up as a portal event.

Purpose: reproduce the "공격" half of the S7 scenario (webpage tamper -> FIM
alert -> 117 restore) from the attack-net side (Kali, 203.0.113.31~39) without
hand-typing ssh/python one-liners each time, and leave one evidence line per
run. It is the attack counterpart of lab/s7/restore/s7_restore.py (restore
side, run on the VM) and follows the same safety style as tools/s12_flood.py.

Two actions:
  new     create <web_root>/zz_s7_<run_id>.html (new file -> FIM 554)
  modify  append one HTML comment to an existing in-baseline file, default
          index.html (changed file -> FIM 550). The remote command reads the
          current baseline manifest first and refuses if --target is not a
          listed baseline file, so this can only touch known web files.

Safety and scope:
- Every run needs --run-id (same charset as s7_restore.py: letters, digits,
  '.', '_', '-', 1-64 chars) and, for `new`, the filename is always
  zz_s7_<run-id>.html -- never a caller-supplied name.
- --target for `modify` must resolve under the web root with no '..' and is
  checked against the remote baseline manifest before anything is written.
- Dry run by default: prints the exact ssh command and remote shell line it
  would run, touches nothing. Pass --execute to actually run it.
- Uses the system `ssh` client (OpenSSH, already on Kali) over subprocess.
  No credentials are read, stored or logged by this script; pass -i/-o
  through --ssh-opt if the environment needs them.
- The optional --access step is a single GET, source-bound like
  tools/s12_probe.py, so the portal records it under the attack-net address.
- Standard library only (Python 3.8+). Every attempted run (dry-run or real,
  success or failure) is appended to --log as one JSON line.

This tool changes files on a real VM web root: confirm the target host, run
id and timing with the team (A owns the VM) before passing --execute, per
the S7 handoff rules (no manager restart during a test window, coordinate
before any real run, keep source IP and pre/post FIM alert counts).
"""
import argparse
import datetime
import http.client
import ipaddress
import json
import math
import os
import re
import shlex
import socket
import subprocess
import sys
import urllib.parse

KST = datetime.timezone(datetime.timedelta(hours=9))

RUN_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def utcnow_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def kst_str():
    return datetime.datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def append_log(path, record):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def to_web_relpath(target):
    """Reject absolute escapes and '..' before the path is even sent remotely."""
    norm = os.path.normpath(target).replace("\\", "/")
    if norm.startswith("/") or norm.startswith("..") or "/../" in ("/" + norm + "/"):
        raise ValueError("target must be a relative path inside the web root, no '..'")
    return norm


def build_remote_command(args, rel_target):
    """One POSIX shell line, run on the VM over ssh. No secrets embedded."""
    web_root = args.web_root.rstrip("/")
    manifest = args.manifest
    if args.action == "new":
        fname = f"zz_s7_{args.run_id}.html"
        marker = f"<!-- s7-tamper-sim run={args.run_id} action=new ts={utcnow_iso()} -->\n"
        dest = f"{web_root}/{fname}"
        # printf avoids shell-quoting surprises in the marker text; dest/web_root
        # are this script's own values, never caller-supplied file content.
        return (
            f"set -e; dest={shlex.quote(dest)}; "
            f"if [ -e \"$dest\" ]; then echo exists_already; exit 3; fi; "
            f"printf '%s' {shlex.quote(marker)} > \"$dest\"; "
            f"chmod 644 \"$dest\"; sha256sum \"$dest\""
        ), fname
    # modify
    full = f"{web_root}/{rel_target}"
    marker = f"<!-- s7-tamper-sim run={args.run_id} action=modify ts={utcnow_iso()} -->\n"
    return (
        f"set -e; full={shlex.quote(full)}; rel={shlex.quote(rel_target)}; "
        f"manifest={shlex.quote(manifest)}; "
        f"grep -qF \"  $rel\" \"$manifest\" || {{ echo not_in_baseline; exit 3; }}; "
        f"[ -f \"$full\" ] || {{ echo target_missing; exit 3; }}; "
        f"before=$(sha256sum \"$full\" | cut -d' ' -f1); "
        f"printf '%s' {shlex.quote(marker)} >> \"$full\"; "
        f"after=$(sha256sum \"$full\" | cut -d' ' -f1); "
        f"echo \"before=$before after=$after\""
    ), rel_target


def run_ssh(args, remote_cmd):
    cmd = ["ssh"]
    for opt in args.ssh_opt:
        cmd += ["-o", opt] if "=" in opt and not opt.startswith("-") else [opt]
    cmd += [args.host, remote_cmd]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.ssh_timeout)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def do_access(args):
    """Optional single GET from the attack-net source, matching s12_probe.py."""
    u = urllib.parse.urlsplit(args.access_url)
    if u.scheme != "http":
        raise SystemExit("--access-url must be http://")
    host, port = u.hostname, u.port or 80
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    conn = http.client.HTTPConnection(
        host, port, timeout=args.access_timeout,
        source_address=(args.source, 0) if args.source else None)
    try:
        conn.connect()
        local = conn.sock.getsockname()[0]
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        return {"status": resp.status, "local_ip": local, "error": None}
    except OSError as e:
        return {"status": 0, "local_ip": args.source, "error": f"{type(e).__name__}:{e}"}
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("action", choices=["new", "modify"])
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--host", required=True, help="ssh target, e.g. haedam@192.0.2.2")
    ap.add_argument("--web-root", default="/home/haedam/haedam-portal-frontend/dist")
    ap.add_argument("--manifest", default="/opt/haedam-s7/baseline.sha256",
                     help="remote baseline manifest, only read to validate --target")
    ap.add_argument("--target", default="index.html",
                     help="modify only: web-root-relative file, must be in the baseline manifest")
    ap.add_argument("--ssh-opt", action="append", default=[],
                     help="extra ssh option, repeatable (e.g. --ssh-opt -i --ssh-opt keyfile)")
    ap.add_argument("--ssh-timeout", type=float, default=15.0)
    ap.add_argument("--execute", action="store_true", help="actually run it (default: dry-run only)")
    ap.add_argument("--access-url", default=None,
                     help="optional GET after tamper (e.g. http://192.0.2.2:5000/)")
    ap.add_argument("--source", default=None,
                     help="attack-net source IPv4 for --access-url, e.g. 203.0.113.31")
    ap.add_argument("--access-timeout", type=float, default=5.0)
    ap.add_argument("--label", required=True)
    ap.add_argument("--log", required=True, help="JSONL evidence log path")
    args = ap.parse_args()

    if not RUN_ID_RE.match(args.run_id):
        raise SystemExit("--run-id must be 1-64 chars of letters, digits, '.', '_', '-'")
    if args.source is not None:
        ipaddress.IPv4Address(args.source)  # reject partial forms like ".31"
    if args.access_url and not args.source:
        print("warning: --access-url without --source leaves the client IP unset", file=sys.stderr)

    rel_target = to_web_relpath(args.target) if args.action == "modify" else None
    remote_cmd, touched = build_remote_command(args, rel_target)

    record = {
        "ts": utcnow_iso(), "ts_kst": kst_str(), "label": args.label, "action": args.action,
        "run_id": args.run_id, "host": args.host, "web_root": args.web_root,
        "touched": touched, "executed": bool(args.execute),
    }

    if not args.execute:
        record["result"] = "dry_run"
        record["remote_command"] = remote_cmd
        print("dry-run (pass --execute to actually run it)")
        print(f"ssh {args.host} {remote_cmd!r}")
    else:
        try:
            rc, out, err = run_ssh(args, remote_cmd)
        except subprocess.TimeoutExpired:
            record["result"] = "error"
            record["reason"] = "ssh_timeout"
        else:
            record["ssh_rc"] = rc
            record["remote_stdout"] = out
            if err:
                record["remote_stderr"] = err
            record["result"] = "ok" if rc == 0 else "error"
        print(json.dumps(record, ensure_ascii=False))

    if args.access_url:
        if not args.execute:
            print(f"dry-run: would GET {args.access_url} from source={args.source}")
            record["access"] = {"result": "dry_run", "url": args.access_url}
        else:
            acc = do_access(args)
            acc["url"] = args.access_url
            record["access"] = acc
            print(json.dumps(acc, ensure_ascii=False))

    append_log(args.log, record)
    return 0 if record.get("result") in ("ok", "dry_run") else 1


if __name__ == "__main__":
    sys.exit(main())
