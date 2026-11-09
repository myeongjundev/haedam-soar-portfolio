#!/usr/bin/env python3
"""S7 117 file restore / quarantine for the portal VM (agent 010).

Changed or deleted files that are in the baseline manifest are restored from
the read-only baseline copy and re-hashed. Files not in the manifest are moved
out of the web root into a quarantine folder. Every action is one JSON line in
the log; file contents are never logged.

Usage (run as root on the portal VM):
  s7_restore.py baseline [--replace]     copy web root -> baseline + manifest
  s7_restore.py restore PATH [--run-id ID]
  s7_restore.py verify                   web root vs manifest (rollback check)
  s7_restore.py purge QUARANTINE_ENTRY   delete one quarantined test entry
  s7_restore.py                          Wazuh active-response mode (JSON on stdin)

Paths come from environment variables (defaults below) so the same script
works on a practice folder.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time

WEB_ROOT = os.environ.get("S7_WEB_ROOT", "/home/haedam/haedam-portal-frontend/dist")
STATE_DIR = os.environ.get("S7_STATE_DIR", "/opt/haedam-s7")
BASELINE_DIR = os.path.join(STATE_DIR, "baseline")
MANIFEST = os.path.join(STATE_DIR, "baseline.sha256")
QUARANTINE_DIR = os.environ.get("S7_QUARANTINE_DIR", "/var/lib/haedam-s7/quarantine")
LOG_FILE = os.environ.get("S7_LOG", "/var/log/haedam-s7/s7-restore.log")
LOCK_FILE = os.path.join(STATE_DIR, ".lock")


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_log(record):
    os.makedirs(os.path.dirname(LOG_FILE), mode=0o750, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_manifest():
    entries = {}
    with open(MANIFEST, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            digest, rel = line.split("  ", 1)
            entries[rel] = digest
    return entries


def web_files():
    for dirpath, _, filenames in os.walk(WEB_ROOT):
        for name in filenames:
            full = os.path.join(dirpath, name)
            yield os.path.relpath(full, WEB_ROOT), full


def to_relpath(path):
    """Map an absolute or web-root-relative path to a safe relative path."""
    root = os.path.realpath(WEB_ROOT)
    full = path if os.path.isabs(path) else os.path.join(root, path)
    # Resolve the parent only: the file itself may be a planted symlink, which
    # must be quarantined as a link, not followed.
    parent = os.path.realpath(os.path.dirname(os.path.normpath(full)))
    full = os.path.join(parent, os.path.basename(os.path.normpath(full)))
    if os.path.commonpath([root, full]) != root or full == root:
        raise ValueError("path_outside_web_root")
    return os.path.relpath(full, root)


def web_owner():
    st = os.stat(WEB_ROOT)
    return st.st_uid, st.st_gid


def cmd_baseline(args):
    if os.path.exists(MANIFEST) and not args.replace:
        print("error baseline_exists (use --replace after an approved deploy)")
        return 2
    staging = tempfile.mkdtemp(prefix="baseline.", dir=STATE_DIR)
    lines = []
    for rel, full in sorted(web_files()):
        if os.path.islink(full):
            continue
        dest = os.path.join(staging, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(full, dest)
        os.chmod(dest, 0o444)
        lines.append(f"{sha256(dest)}  {rel}")
    if os.path.exists(BASELINE_DIR):
        shutil.rmtree(BASELINE_DIR)
    os.rename(staging, BASELINE_DIR)
    os.chmod(BASELINE_DIR, 0o755)
    with open(MANIFEST, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(MANIFEST, 0o444)
    write_log({"ts": utcnow(), "action": "baseline", "files": len(lines),
               "manifest_sha256": sha256(MANIFEST), "result": "ok"})
    print(f"ok baseline files={len(lines)} manifest_sha256={sha256(MANIFEST)}")
    return 0


def restore_one(rel, run_id):
    started = time.monotonic()
    manifest = load_manifest()
    full = os.path.join(WEB_ROOT, rel)
    rec = {"ts": utcnow(), "run_id": run_id, "path": rel}
    exists = os.path.lexists(full)
    if exists and not os.path.islink(full) and os.path.isdir(full):
        rec.update(action="none", result="error", reason="is_directory")
    elif rel in manifest:
        expected = manifest[rel]
        src = os.path.join(BASELINE_DIR, rel)
        before = sha256(full) if exists and not os.path.islink(full) else None
        rec.update(action="restore", sha256_before=before, sha256_expected=expected)
        if before == expected:
            rec.update(result="ok", reason="already_matches_baseline")
        elif not os.path.isfile(src) or sha256(src) != expected:
            rec.update(result="error", reason="baseline_missing_or_tampered")
        else:
            os.makedirs(os.path.dirname(full), exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".s7restore.", dir=os.path.dirname(full))
            os.close(fd)
            shutil.copyfile(src, tmp)
            os.chmod(tmp, 0o644)
            os.chown(tmp, *web_owner())
            if os.path.islink(full):
                os.unlink(full)
            os.replace(tmp, full)
            after = sha256(full)
            rec.update(sha256_after=after, result="ok" if after == expected else "error")
            if after != expected:
                rec["reason"] = "hash_mismatch_after_restore"
    elif exists:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        entry = f"{stamp}_{run_id or 'manual'}"
        dest = os.path.join(QUARANTINE_DIR, entry, rel)
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        islink = os.path.islink(full)
        before = None if islink else sha256(full)
        size = None if islink else os.path.getsize(full)
        shutil.move(full, dest)
        if not islink:
            os.chmod(dest, 0o400)
        gone = not os.path.lexists(full)
        rec.update(action="quarantine", sha256_before=before, size=size,
                   symlink=islink, quarantine_entry=entry,
                   result="ok" if gone else "error")
        if not gone:
            rec["reason"] = "still_in_web_root"
    else:
        rec.update(action="none", result="ok", reason="not_in_baseline_and_absent")
    rec["duration_ms"] = round((time.monotonic() - started) * 1000)
    write_log(rec)
    return rec


def cmd_restore(args):
    try:
        rel = to_relpath(args.path)
    except ValueError as e:
        write_log({"ts": utcnow(), "run_id": args.run_id, "path": args.path,
                   "action": "none", "result": "error", "reason": str(e)})
        print(f"error {e}")
        return 2
    with open(LOCK_FILE, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        rec = restore_one(rel, args.run_id)
    print(json.dumps(rec, ensure_ascii=False))
    print(rec["result"])
    return 0 if rec["result"] == "ok" else 1


def cmd_verify(_args):
    manifest = load_manifest()
    seen = {}
    for rel, full in web_files():
        seen[rel] = None if os.path.islink(full) else sha256(full)
    changed = sorted(r for r, d in manifest.items() if r in seen and seen[r] != d)
    missing = sorted(r for r in manifest if r not in seen)
    extra = sorted(r for r in seen if r not in manifest)
    ok = not (changed or missing or extra)
    rec = {"ts": utcnow(), "action": "verify", "files": len(manifest),
           "changed": changed, "missing": missing, "extra": extra,
           "result": "ok" if ok else "mismatch"}
    write_log(rec)
    print(json.dumps(rec, ensure_ascii=False))
    print(rec["result"])
    return 0 if ok else 1


def cmd_purge(args):
    entry = os.path.basename(args.entry.rstrip("/"))
    target = os.path.join(QUARANTINE_DIR, entry)
    if not entry or not os.path.isdir(target):
        print("error no_such_quarantine_entry")
        return 2
    count = sum(len(f) for _, _, f in os.walk(target))
    shutil.rmtree(target)
    write_log({"ts": utcnow(), "action": "purge", "quarantine_entry": entry,
               "files": count, "result": "ok"})
    print(f"ok purge {entry} files={count}")
    return 0


def active_response():
    """Wazuh 4.x stateless active response: one JSON message on stdin."""
    os.makedirs(STATE_DIR, mode=0o755, exist_ok=True)
    msg = json.loads(sys.stdin.readline())
    if msg.get("command") != "add":
        return 0
    params = msg.get("parameters", {})
    alert = params.get("alert", {})
    path = alert.get("syscheck", {}).get("path")
    extra = params.get("extra_args") or []
    run_id = extra[0] if extra else alert.get("id")
    if not path:
        write_log({"ts": utcnow(), "run_id": run_id, "action": "none",
                   "result": "error", "reason": "no_syscheck_path"})
        return 1
    return cmd_restore(argparse.Namespace(path=path, run_id=run_id))


def main():
    if len(sys.argv) == 1:
        return active_response()
    p = argparse.ArgumentParser(description="S7 117 restore / quarantine")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("baseline")
    b.add_argument("--replace", action="store_true")
    r = sub.add_parser("restore")
    r.add_argument("path")
    r.add_argument("--run-id")
    sub.add_parser("verify")
    g = sub.add_parser("purge")
    g.add_argument("entry")
    args = p.parse_args()
    if os.geteuid() != 0:
        print("error must_run_as_root")
        return 2
    os.makedirs(STATE_DIR, mode=0o755, exist_ok=True)
    return {"baseline": cmd_baseline, "restore": cmd_restore,
            "verify": cmd_verify, "purge": cmd_purge}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
