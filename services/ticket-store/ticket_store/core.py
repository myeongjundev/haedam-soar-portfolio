"""check/record rules for the D n8n result-log (design sections 2, 3 and 5).

n8n only ever sees and changes live tickets; sample tickets are for the screen.
"""
from datetime import datetime
import hashlib
import json

from . import db

APPLIED = db.APPLIED
TICKET_TIMES = ("first_attack_at", "condition_met_at", "detected_at", "received_at")


class Conflict(Exception):
    """Same Idempotency-Key reused with a different body."""


class NoActionToUpdate(Exception):
    """effect/released stage without a matching active action on this route."""


class InvalidTransition(Exception):
    """A record would mix asset scopes or reuse an inconsistent restored ticket."""


class StaleEffect(Exception):
    """Effect evidence predates the matching active action."""


def _instant(value):
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.astimezone()


_action_key = db.action_key
_active_actions = db.active_actions


def _action_ref(row, with_via=False):
    ref = {"bot": row["bot"], "via": row["via"], "action": _action_key(row)[2], "target": row["target"]}
    if not with_via:
        ref["result"] = row["result"]
    return ref


def check(conn, group_key, seat=None):
    if seat:
        row = conn.execute("SELECT ticket_id, status FROM tickets WHERE seat = ? AND group_key = ? AND status != 'closed' "
                           "AND data_origin = 'live'",
                           (seat, group_key)).fetchone()
        if row is None:
            return {"ok": True, "exists": False, "ticket_id": None, "status": None, "applied_actions": []}
        return {"ok": True, "exists": True, "ticket_id": row["ticket_id"], "status": row["status"],
                "applied_actions": [_action_ref(a) for a in _active_actions(conn, row["ticket_id"])]}
    rows = conn.execute("SELECT seat, ticket_id, status FROM tickets WHERE group_key = ? AND status != 'closed' "
                        "AND data_origin = 'live' ORDER BY seat", (group_key,)).fetchall()
    return _all_seats(conn, rows)


def check_target(conn, target):
    """Live tickets of any seat that still hold an active action on this target.

    Closed tickets are included when an action is still active: a ticket closed before the release
    (older data) must not hide the block.

    Release hold: A (S1) blocks an IP under group_key=username, B/D block the same IP under
    group_key=src_ip, so looking up by group_key alone misses other seats' blocks.
    """
    rows = conn.execute("SELECT DISTINCT t.seat, t.ticket_id, t.status FROM tickets t JOIN actions a "
                        "ON a.ticket_id = t.ticket_id WHERE a.target = ? "
                        "AND t.data_origin = 'live' ORDER BY t.seat, t.ticket_id", (target,)).fetchall()
    result = _all_seats(conn, rows, target)
    result["tickets"] = [t for t in result["tickets"] if t["active_actions"]]
    return result


def _all_seats(conn, rows, target=None):
    return {"ok": True, "tickets": [
        {"seat": r["seat"], "ticket_id": r["ticket_id"], "status": r["status"],
         "active_actions": [_action_ref(a, with_via=True) for a in _active_actions(conn, r["ticket_id"])
                            if target is None or a["target"] == target]}
        for r in rows]}


def active_for_resource(conn, resource):
    """All recorded live claims, across grouping keys. Close alone is not release.

    This is a read snapshot, not a lock/reservation or permission to unblock.
    """
    tickets = []
    rows = conn.execute("SELECT seat, ticket_id, status FROM tickets WHERE asset_id = ? "
                        "AND data_origin = 'live' ORDER BY seat, ticket_id", (resource["asset_id"],)).fetchall()
    for row in rows:
        actions = [a for a in _active_actions(conn, row["ticket_id"])
                   if a["via"] == resource["via"] and _action_key(a)[2] == resource["action"]
                   and a["target"] == resource["target"]]
        if actions:
            tickets.append({"seat": row["seat"], "ticket_id": row["ticket_id"], "status": row["status"],
                            "active_actions": [_action_ref(a, with_via=True) for a in actions]})
    return {"ok": True, "resource": resource, "tickets": tickets}


def _body_hash(body):
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _new_ticket_id(conn, now):
    day = datetime.fromisoformat(now).strftime("%Y%m%d")
    row = conn.execute("SELECT MAX(ticket_id) FROM tickets WHERE ticket_id LIKE ? AND data_origin = 'live'",
                       (f"T-{day}-%",)).fetchone()
    last = int(row[0][-4:]) if row[0] else 0
    return f"T-{day}-{last + 1:04d}"


def _ticket_holding_event(conn, seat, group_key, event_ids, current_ticket=None):
    """Only the same seat and group_key: two seats may record the same Graylog event."""
    current_match = None
    for ticket_id, stored in conn.execute("SELECT ticket_id, event_ids FROM tickets WHERE seat = ? AND group_key = ? "
                                          "AND data_origin = 'live'",
                                          (seat, group_key)):
        if set(json.loads(stored)) & set(event_ids):
            if ticket_id == current_ticket:
                current_match = ticket_id
                continue
            return ticket_id
    return current_match


def record(conn, body, idempotency_key, now=None):
    """Returns (http_status, response). Body must already pass validate.record_body."""
    now = now or db.now_iso()
    body_hash = _body_hash(body)
    conn.execute("BEGIN IMMEDIATE")
    try:
        seen = conn.execute("SELECT body_hash, http_status, response FROM idempotency WHERE key = ?",
                            (idempotency_key,)).fetchone()
        if seen:
            conn.rollback()
            if seen["body_hash"] != body_hash:
                raise Conflict(idempotency_key)
            return seen["http_status"], json.loads(seen["response"])
        status_code, response = _apply(conn, body, idempotency_key, now)
        conn.execute("INSERT INTO idempotency (key, body_hash, http_status, response, created_at) VALUES (?, ?, ?, ?, ?)",
                     (idempotency_key, body_hash, status_code, json.dumps(response), now))
        conn.execute("INSERT INTO meta (key, value) VALUES ('last_record_at', ?) "
                     "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (now,))
        conn.commit()
        return status_code, response
    except BaseException:
        if conn.in_transaction:
            conn.rollback()
        raise


def _starts_new_round(ticket, body):
    """Reserve the fresh detected round before D calls a target; also accept direct applied records."""
    return (ticket is not None and ticket["status"] == "restored"
            and (body["stage"] == "detected"
                 or body["stage"] == "applied" and body["action"]["result"] in APPLIED))


def _close_for_new_round(conn, ticket, new_ticket_id, now):
    conn.execute("UPDATE tickets SET status = 'closed', closed_at = ?, close_note = ?, updated_at = ? "
                 "WHERE ticket_id = ?", (now, f"재차단: 새 회차로 분리 ({new_ticket_id})", now, ticket["ticket_id"]))


def _apply(conn, body, key, now):
    ticket = conn.execute("SELECT * FROM tickets WHERE seat = ? AND group_key = ? AND status != 'closed' "
                          "AND data_origin = 'live'", (body["seat"], body["group_key"])).fetchone()
    created = False
    reserved_id = None
    if ticket is not None and ticket["asset_id"] != body["asset_id"]:
        raise InvalidTransition("asset_id differs from the existing ticket; use a distinct group_key")
    # An old event must not be merged into an already-active new round.
    if body["stage"] in ("detected", "applied"):
        holder = _ticket_holding_event(conn, body["seat"], body["group_key"], body["event_ids"],
                                       ticket["ticket_id"] if ticket else None)
        if holder and (ticket is None or holder != ticket["ticket_id"] or ticket["status"] == "restored"):
            status = conn.execute("SELECT status FROM tickets WHERE ticket_id = ?", (holder,)).fetchone()[0]
            return 200, {"ok": True, "ticket_id": holder, "created": False, "duplicate": True, "status": status}
    if _starts_new_round(ticket, body):
        if _active_actions(conn, ticket["ticket_id"]):
            raise InvalidTransition("restored ticket still has active actions")
        # The open-ticket index allows one per seat and group_key, so the old round closes first.
        reserved_id = _new_ticket_id(conn, now)
        _close_for_new_round(conn, ticket, reserved_id, now)
        ticket = None
    if ticket is None:
        holder = _ticket_holding_event(conn, body["seat"], body["group_key"], body["event_ids"])
        if holder:
            # Same Graylog decision re-sent after its ticket closed or moved: never open a second ticket.
            status = conn.execute("SELECT status FROM tickets WHERE ticket_id = ?", (holder,)).fetchone()[0]
            return 200, {"ok": True, "ticket_id": holder, "created": False, "duplicate": True, "status": status}
        ticket_id = reserved_id or _new_ticket_id(conn, now)
        db.insert_ticket(conn, {
            "ticket_id": ticket_id, "status": "open", "data_origin": "live", "created_at": now, "updated_at": now,
            **{name: body.get(name) for name in ("seat", "case_id", "group_key", "title", "asset_id", "src_ip",
                                                   "username", "reason", "event_ids", *TICKET_TIMES)},
            "actions": []})
        ticket = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
        created = True
    else:
        merged = json.loads(ticket["event_ids"]) + [e for e in body["event_ids"] if e not in json.loads(ticket["event_ids"])]
        conn.execute("UPDATE tickets SET event_ids = ? WHERE ticket_id = ?", (json.dumps(merged, ensure_ascii=False),
                                                                             ticket["ticket_id"]))
        for name in TICKET_TIMES:
            if body.get(name) and not ticket[name]:
                conn.execute(f"UPDATE tickets SET {name} = ? WHERE ticket_id = ?", (body[name], ticket["ticket_id"]))

    ticket_id = ticket["ticket_id"]
    duplicate = _apply_action(conn, ticket, body["stage"], body["action"], key, now)
    status = conn.execute("SELECT status FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()[0]
    conn.execute("UPDATE tickets SET updated_at = ? WHERE ticket_id = ?", (now, ticket_id))
    return (201 if created else 200), {"ok": True, "ticket_id": ticket_id, "created": created,
                                       "duplicate": duplicate, "status": status}


def _set_status(conn, ticket_id, new_status, time_field, value):
    conn.execute(f"UPDATE tickets SET status = ?, {time_field} = COALESCE({time_field}, ?) WHERE ticket_id = ?",
                 (new_status, value, ticket_id))


def _apply_action(conn, ticket, stage, action, key, now):
    """Returns the duplicate flag. Status only moves forward (design section 2)."""
    ticket_id, status = ticket["ticket_id"], ticket["status"]
    if stage == "detected":
        return False
    active = _active_actions(conn, ticket_id)
    if stage == "effect":
        line = next((a for a in active if _action_key(a) == _action_key(action)), None)
        if line is None:
            raise NoActionToUpdate()
        since = line["finished_at"] or line["requested_at"] or line["recorded_at"]
        if _instant(action["effect_verified_at"]) < _instant(since):
            raise StaleEffect()
        conn.execute("UPDATE actions SET effect_verified = ?, effect_verified_at = ? WHERE id = ?",
                     (int(action["effect_verified"]), action["effect_verified_at"], line["id"]))
        if action["effect_verified"] and status == "responding":
            _set_status(conn, ticket_id, "verified", "verified_at", action["effect_verified_at"])
        return False
    if stage == "applied" and action["result"] in APPLIED:
        if status == "restored":
            raise InvalidTransition("restored ticket must be closed before recording a new application cycle")
        same = next((a for a in active if _action_key(a) == _action_key(action)), None)
        if same:
            db.insert_action(conn, ticket_id, action, key, now, duplicate=True)
            return True
    if action["result"] == "released" and not any(
            _action_key(a) == _action_key(action, released=True) for a in active):
        raise NoActionToUpdate()
    db.insert_action(conn, ticket_id, action, key, now)
    if action["result"] in APPLIED and status == "open":
        _set_status(conn, ticket_id, "responding", "responded_at", action["finished_at"] or now)
    elif action["result"] == "released" and status in ("responding", "verified") and not _active_actions(conn, ticket_id):
        # S10: releasing pfSense while the portal block is still active is not a restore yet.
        _set_status(conn, ticket_id, "restored", "restored_at", action["finished_at"] or now)
    return False
