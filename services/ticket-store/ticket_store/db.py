"""SQLite storage for the 114 ticket store.

Design: docs/C-티켓저장소-설계.md. Contract: contracts/ticket*.schema.json.
Read functions and close_ticket are shared by the dashboard; record/check
logic for n8n lives in the core module.
"""
from datetime import datetime
import json
import sqlite3

STATUSES = ("open", "responding", "verified", "restored", "closed")
CLOSABLE = ("verified", "restored")
APPLIED = ("applied", "already_applied")
TIME_FIELDS = ("first_attack_at", "condition_met_at", "detected_at", "received_at",
               "responded_at", "verified_at", "restored_at")
ACTION_FIELDS = ("bot", "target", "via", "action", "result", "applied_verified", "effect_verified",
                 "requested_at", "finished_at", "effect_verified_at", "n8n_execution_id", "detail")

SCHEMA = """
CREATE TABLE IF NOT EXISTS tickets (
    ticket_id TEXT PRIMARY KEY,
    seat TEXT NOT NULL,
    case_id TEXT NOT NULL,
    group_key TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    src_ip TEXT,
    username TEXT,
    reason TEXT,
    event_ids TEXT NOT NULL,
    first_attack_at TEXT, condition_met_at TEXT, detected_at TEXT, received_at TEXT,
    responded_at TEXT, verified_at TEXT, restored_at TEXT,
    closed_at TEXT, close_note TEXT,
    data_origin TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS one_open_ticket ON tickets(seat, group_key, data_origin) WHERE status != 'closed';
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id TEXT NOT NULL REFERENCES tickets(ticket_id),
    action_id TEXT NOT NULL,
    bot TEXT NOT NULL, target TEXT NOT NULL, via TEXT NOT NULL, action TEXT NOT NULL, result TEXT NOT NULL,
    applied_verified INTEGER, effect_verified INTEGER,
    requested_at TEXT, finished_at TEXT, effect_verified_at TEXT,
    n8n_execution_id TEXT NOT NULL, detail TEXT,
    duplicate INTEGER NOT NULL DEFAULT 0,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
    key TEXT PRIMARY KEY,
    body_hash TEXT NOT NULL,
    http_status INTEGER NOT NULL,
    response TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS s12_comparisons (
    run_id TEXT PRIMARY KEY,
    ticket_id TEXT NOT NULL REFERENCES tickets(ticket_id),
    data_origin TEXT NOT NULL CHECK(data_origin IN ('live', 'sample')),
    recorded_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
"""


class NotFound(Exception):
    pass


class InvalidTransition(Exception):
    pass


def connect(path):
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(SCHEMA)
    return conn


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def seconds_between(start, end):
    if not start or not end:
        return None
    return round((datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds(), 3)


def _bool(value):
    return None if value is None else bool(value)


def _action_dict(row):
    item = {name: row[name] for name in ACTION_FIELDS if name != "detail" or row[name] is not None}
    item["applied_verified"] = _bool(row["applied_verified"])
    item["effect_verified"] = _bool(row["effect_verified"])
    item.update(action_id=row["action_id"], duplicate=bool(row["duplicate"]), recorded_at=row["recorded_at"])
    return item


def _actions(conn, ticket_id):
    rows = conn.execute("SELECT * FROM actions WHERE ticket_id = ? ORDER BY id", (ticket_id,))
    return [_action_dict(row) for row in rows]


def _ticket_dict(conn, row):
    ticket = {"schema_version": "1.0"}
    for name in ("ticket_id", "seat", "case_id", "group_key", "title", "status", "asset_id", "src_ip", "username"):
        ticket[name] = row[name]
    ticket["event_ids"] = json.loads(row["event_ids"])
    if row["reason"] is not None:
        ticket["reason"] = row["reason"]
    for name in TIME_FIELDS:
        ticket[name] = row[name]
    if row["closed_at"] is not None:
        ticket["closed_at"] = row["closed_at"]
        ticket["close_note"] = row["close_note"]
    ticket["actions"] = _actions(conn, row["ticket_id"])
    for name in ("data_origin", "created_at", "updated_at"):
        ticket[name] = row[name]
    return ticket


def get_ticket(conn, ticket_id):
    row = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
    if row is None:
        raise NotFound(ticket_id)
    return _ticket_dict(conn, row)


def list_tickets(conn, seat=None, case_id=None, statuses=None, include_sample=False, limit=50):
    """Ticket summaries for the dashboard list, newest update first."""
    where, args = [], []
    if seat:
        where.append("seat = ?"); args.append(seat)
    if case_id:
        where.append("case_id = ?"); args.append(case_id)
    if statuses:
        where.append(f"status IN ({','.join('?' * len(statuses))})"); args.extend(statuses)
    if not include_sample:
        where.append("data_origin = 'live'")
    sql = "SELECT * FROM tickets" + (" WHERE " + " AND ".join(where) if where else "")
    rows = conn.execute(sql + " ORDER BY updated_at DESC, ticket_id DESC LIMIT ?", (*args, limit)).fetchall()
    items = []
    for row in rows:
        last = conn.execute("SELECT result FROM actions WHERE ticket_id = ? ORDER BY id DESC LIMIT 1",
                            (row["ticket_id"],)).fetchone()
        items.append({
            "ticket_id": row["ticket_id"], "seat": row["seat"], "case_id": row["case_id"], "title": row["title"],
            "status": row["status"], "group_key": row["group_key"],
            "last_result": last["result"] if last else None,
            "mttd_seconds": seconds_between(row["condition_met_at"], row["detected_at"]),
            "mttr_seconds": seconds_between(row["detected_at"], row["verified_at"]),
            "data_origin": row["data_origin"], "updated_at": row["updated_at"],
        })
    return items


def status_counts(conn, include_sample=False):
    sql = "SELECT status, COUNT(*) FROM tickets" + ("" if include_sample else " WHERE data_origin = 'live'")
    counts = dict.fromkeys(STATUSES, 0)
    counts.update(dict(conn.execute(sql + " GROUP BY status").fetchall()))
    return counts


def last_record_at(conn):
    row = conn.execute("SELECT value FROM meta WHERE key = 'last_record_at'").fetchone()
    return row["value"] if row else None


def insert_ticket(conn, ticket):
    """Store a complete ticket (samples now, core record logic later)."""
    columns = ["ticket_id", "seat", "case_id", "group_key", "title", "status", "asset_id", "src_ip", "username",
               "reason", "event_ids", *TIME_FIELDS, "closed_at", "close_note", "data_origin", "created_at", "updated_at"]
    values = {**ticket, "event_ids": json.dumps(ticket["event_ids"], ensure_ascii=False)}
    conn.execute(f"INSERT INTO tickets ({','.join(columns)}) VALUES ({','.join('?' * len(columns))})",
                 [values.get(name) for name in columns])
    for action in ticket.get("actions", []):
        insert_action(conn, ticket["ticket_id"], action, action["action_id"], action["recorded_at"],
                      duplicate=action.get("duplicate", False))


def insert_action(conn, ticket_id, action, action_id, recorded_at, duplicate=False):
    values = [action.get(name) for name in ACTION_FIELDS]
    conn.execute(f"INSERT INTO actions (ticket_id, action_id, {','.join(ACTION_FIELDS)}, duplicate, recorded_at) "
                 f"VALUES (?, ?, {','.join('?' * len(ACTION_FIELDS))}, ?, ?)",
                 [ticket_id, action_id, *values, int(duplicate), recorded_at])


def action_key(action, released=False):
    releases = {"unblock": "block", "unlock": "lock", "restore": "quarantine"}
    name = releases.get(action["action"], action["action"]) if released else action["action"]
    if action["via"] == "pfsense" and name == "fw_block":
        name = "block"  # Read legacy rows without rewriting evidence.
    return action["bot"], action["via"], name, action["target"]


def active_actions(conn, ticket_id):
    """Applied lines whose target has not been released by the same bot and via since.

    via is part of the key: S10 blocks the same IP with bot 112 twice, through the
    portal and through pfSense, and each must be applied and released on its own.
    One place decides "still active": record (duplicates, effect), check and close all use it.
    """
    rows = conn.execute("SELECT * FROM actions WHERE ticket_id = ? AND duplicate = 0 ORDER BY id", (ticket_id,)).fetchall()
    active = {}
    for row in rows:
        if row["result"] in APPLIED:
            active[action_key(row)] = row
        elif row["result"] == "released":
            active.pop(action_key(row, released=True), None)
    return list(active.values())


def close_ticket(conn, ticket_id, note, now=None):
    """Human close from the dashboard. Only verified or restored tickets can close, and only
    when no applied action is left unreleased (a closed ticket would hide a live block)."""
    ticket = get_ticket(conn, ticket_id)
    if ticket["status"] not in CLOSABLE:
        raise InvalidTransition(f"{ticket['status']} cannot be closed")
    if active_actions(conn, ticket_id):
        raise InvalidTransition("active action remains")
    now = now or now_iso()
    with conn:
        conn.execute("UPDATE tickets SET status = 'closed', closed_at = ?, close_note = ?, updated_at = ? "
                     "WHERE ticket_id = ?", (now, note, now, ticket_id))
    return get_ticket(conn, ticket_id)


CANCEL_PREFIX = "[취소] "
CLOSE_NOTE_MAX = 200
UNCERTAIN_RESULTS = ("applied", "already_applied", "failed")   # failed is uncertain: the target may be half changed


def cancel_ticket(conn, ticket_id, note, now=None):
    """Human cancel of a live test ticket that never acted: status open and no applied, already_applied or
    failed line (no lines, or only rejected). Closes it with a note; lines are kept, nothing is faked."""
    if len(CANCEL_PREFIX) + len(note) > CLOSE_NOTE_MAX:
        raise ValueError("note too long")
    now = now or now_iso()
    conn.execute("BEGIN IMMEDIATE")   # no record may add an action between the check and the update
    try:
        ticket = get_ticket(conn, ticket_id)
        if ticket["data_origin"] != "live":
            raise InvalidTransition("only live tickets can be cancelled")
        if ticket["status"] != "open":
            raise InvalidTransition(f"{ticket['status']} cannot be cancelled")
        if any(a["result"] in UNCERTAIN_RESULTS for a in ticket["actions"]):
            raise InvalidTransition("an action was applied or failed; release it and close instead")
        conn.execute("UPDATE tickets SET status = 'closed', closed_at = ?, close_note = ?, updated_at = ? "
                     "WHERE ticket_id = ?", (now, CANCEL_PREFIX + note, now, ticket_id))
        conn.commit()
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise
    return get_ticket(conn, ticket_id)


def dashboard_ticket(conn, ticket_id, page=1, limit=50):
    """Read bounded history for the dashboard; the public API remains unchanged."""
    row = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
    if row is None:
        raise NotFound(ticket_id)
    ticket = dict(row)
    ticket["event_ids"] = json.loads(row["event_ids"])
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    rows = conn.execute("SELECT * FROM actions WHERE ticket_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                        (ticket_id, limit + 1, (page - 1) * limit)).fetchall()
    ticket["actions"] = [_action_dict(row) for row in rows[:limit]]
    ticket["more_actions"] = len(rows) > limit
    ticket["action_page"] = page
    last = conn.execute("SELECT result FROM actions WHERE ticket_id=? AND duplicate=0 ORDER BY id DESC LIMIT 1", (ticket_id,)).fetchone()
    ticket["last_result"] = last["result"] if last else None
    return ticket


# Canonical target keys match action_key, including the legacy pfSense spelling.
_WORK_CTE = """
WITH normal AS (
 SELECT a.*, CASE WHEN action = 'unblock' THEN 'block'
                  WHEN action = 'unlock' THEN 'lock'
                  WHEN action = 'restore' THEN 'quarantine'
                  WHEN action = 'fw_block' AND via = 'pfsense' THEN 'block'
                  ELSE action END AS kind
 FROM actions a WHERE duplicate = 0
), latest AS (
 SELECT n.*, ROW_NUMBER() OVER (PARTITION BY ticket_id, bot, via, kind, target ORDER BY id DESC) AS rn
 FROM normal n
), lifecycle AS (
 SELECT n.*, ROW_NUMBER() OVER (PARTITION BY ticket_id, bot, via, kind, target ORDER BY id DESC) AS rn
 FROM normal n WHERE result IN ('applied','already_applied','released')
), flags AS (
 SELECT t.ticket_id,
  EXISTS(SELECT 1 FROM latest a WHERE a.ticket_id=t.ticket_id AND a.rn=1 AND
          (a.result IN ('failed','rejected') OR (a.result IN ('applied','already_applied') AND a.applied_verified=0))) AS failed,
  EXISTS(SELECT 1 FROM lifecycle a WHERE a.ticket_id=t.ticket_id AND a.rn=1 AND a.result IN ('applied','already_applied') AND a.effect_verified IS NULL) AS effect_wait,
  EXISTS(SELECT 1 FROM lifecycle a WHERE a.ticket_id=t.ticket_id AND a.rn=1 AND a.result IN ('applied','already_applied') AND a.effect_verified=0) AS effect_failed,
  EXISTS(SELECT 1 FROM lifecycle a WHERE a.ticket_id=t.ticket_id AND a.rn=1 AND a.result IN ('applied','already_applied') AND a.kind IN ('block','lock','quarantine')) AS restore_wait,
  EXISTS(SELECT 1 FROM lifecycle a JOIN lifecycle b ON a.target=b.target AND a.via=b.via AND a.kind=b.kind
         JOIN tickets other ON other.ticket_id=b.ticket_id
         WHERE a.ticket_id=t.ticket_id AND a.rn=1 AND b.rn=1 AND a.kind IN ('block','lock')
           AND a.result IN ('applied','already_applied') AND b.result IN ('applied','already_applied')
           AND other.seat!=t.seat AND other.asset_id=t.asset_id
           AND other.data_origin=t.data_origin) AS related
 FROM tickets t WHERE t.status!='closed'
)
"""


def dashboard_work(conn, seat=None, include_sample=False, page=1, limit=50):
    conditions = ["t.status != 'closed'", "(f.failed OR f.effect_wait OR f.effect_failed OR f.restore_wait OR f.related)"]
    args = []
    if seat:
        conditions.append("t.seat = ?")
        args.append(seat)
    if not include_sample:
        conditions.append("t.data_origin = 'live'")
    where = " AND ".join(conditions)
    base = _WORK_CTE + " SELECT t.*, f.failed, f.effect_wait, f.effect_failed, f.restore_wait, f.related FROM tickets t JOIN flags f ON f.ticket_id=t.ticket_id WHERE " + where
    page, limit = max(1, page), min(max(1, limit), 200)
    rows = conn.execute(base + " ORDER BY f.failed DESC, f.effect_failed DESC, t.updated_at DESC, t.ticket_id DESC LIMIT ? OFFSET ?", (*args, limit + 1, (page - 1) * limit)).fetchall()
    return {"items": [dict(r) for r in rows[:limit]], "more": len(rows) > limit, "page": page}


def dashboard_cases(conn, seat=None, include_sample=False):
    groups = (("A", ("S1", "S4"), "기밀성"), ("B", ("S8", "S10"), "NIDS"),
              ("C", ("S7",), "무결성"), ("D", ("S12",), "가용성"))
    result = []
    for group_seat, cases, principle in groups:
        if seat and group_seat != seat:
            continue
        placeholders = ','.join('?' for _ in cases)
        where = f"seat = ? AND case_id IN ({placeholders})" + ("" if include_sample else " AND data_origin = 'live'")
        args = (group_seat, *cases)
        sources = []
        for origin in (("live", "sample") if include_sample else ("live",)):
            origin_where = where + " AND data_origin = ?"
            origin_args = (*args, origin)
            count = conn.execute("SELECT COUNT(*) AS n FROM tickets WHERE " + origin_where + " AND status != 'closed'", origin_args).fetchone()["n"]
            latest = conn.execute("SELECT ticket_id, title, status, updated_at, data_origin FROM tickets WHERE " + origin_where + " ORDER BY updated_at DESC, ticket_id DESC LIMIT 1", origin_args).fetchone()
            comparisons = 0
            if "S12" in cases:  # Only S12 registers before/after comparisons; other cases stay "no data".
                comparisons = conn.execute(
                    "SELECT COUNT(*) AS n FROM s12_comparisons s JOIN tickets t ON t.ticket_id = s.ticket_id"
                    " WHERE t.seat = ? AND t.case_id = 'S12' AND s.data_origin = ? AND t.data_origin = s.data_origin",
                    (group_seat, origin)).fetchone()["n"]
            sources.append({"origin": origin, "count": count, "latest": dict(latest) if latest else None,
                            "comparisons": comparisons})
        result.append({"seat": group_seat, "cases": cases, "principle": principle, "sources": sources})
    return result


def dashboard_has_active(conn, ticket_id):
    sql = _WORK_CTE.replace("FROM actions a WHERE duplicate = 0", "FROM actions a WHERE duplicate = 0 AND ticket_id = ?") + " SELECT 1 FROM lifecycle WHERE rn=1 AND result IN ('applied','already_applied') LIMIT 1"
    return conn.execute(sql, (ticket_id,)).fetchone() is not None
