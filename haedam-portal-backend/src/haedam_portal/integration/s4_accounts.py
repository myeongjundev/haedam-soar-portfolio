"""Opt-in synthetic-account response. Separate release authority; no password handling."""
import hmac
import re

from flask import current_app, request
from sqlalchemy import func, select

from . import bp, in_response_networks, replayed, request_digests
from .events import emit
from ..common import body, client_ip, fail, ok
from ..models import db, LoginSession, ResponseReceipt, S4AccountClaim, User, now


def authorize(username, release=False):
    cfg = current_app.config
    expected = cfg.get("S4_RELEASE_KEY" if release else "RESPONSE_API_KEY", "")
    # Misconfigured key reuse disables both operations, not just release.
    valid_keys = (len(cfg.get("RESPONSE_API_KEY", "")) >= 32 and len(cfg.get("S4_RELEASE_KEY", "")) >= 32
                  and cfg["RESPONSE_API_KEY"] != cfg["S4_RELEASE_KEY"])
    if (cfg.get("S4_ENABLED") is not True or not valid_keys or not expected
            or not in_response_networks(client_ip())
            or not hmac.compare_digest(expected, request.headers.get("X-Response-Key", ""))):
        fail(403, "FORBIDDEN", "S4 lab authority required.")
    if not re.fullmatch(r"zz_[a-z0-9_]{1,37}", username) or username not in cfg.get("S4_ACCOUNT_ALLOWLIST", []):
        fail(403, "FORBIDDEN", "Account outside S4 lab scope.")


def account(username):
    target = db.session.scalar(select(User).where(User.username == username).with_for_update())
    if not target:
        fail(404, "NOT_FOUND", "Account not found.")
    if target.role not in {"citizen", "staff"}:
        fail(403, "FORBIDDEN", "Protected account role.")
    return target


def state(target):
    claim = db.session.get(S4AccountClaim, target.id)
    sessions = db.session.scalar(select(func.count()).select_from(LoginSession).where(
        LoginSession.user_id == target.id, LoginSession.expires_at > now()))
    return {"user_id": target.id, "username": target.username, "locked": target.locked,
            "active_sessions": sessions, "owner_ticket_id": claim.ticket_id if claim else None}


@bp.get("/s4/accounts/<username>")
def s4_status(username):
    authorize(username)
    return ok(state(account(username)))


@bp.post("/s4/accounts/<username>/<action>")
def s4_change(username, action):
    if action not in {"lock", "unlock"}:
        fail(404, "NOT_FOUND", "Unknown S4 action.")
    authorize(username, action == "unlock")
    data = body()
    required = {"user_id", "ticket_id"} | ({"reason_code"} if action == "unlock" else set())
    if (set(data) != required or type(data.get("user_id")) is not int or data["user_id"] < 1
            or not isinstance(data.get("ticket_id"), str) or not re.fullmatch(r"T-\d{8}-\d{4}", data["ticket_id"])
            or action == "unlock" and data.get("reason_code") != "false_positive"):
        fail(400, "VALIDATION_ERROR", "Invalid S4 mutation request.")
    key, fingerprint = request_digests({"s4": username, "action": action, "data": data})
    target = account(username)
    if target.id != data["user_id"]:
        fail(409, "CONFLICT", "Account identity changed.")
    previous = replayed(key, fingerprint)
    if previous:
        return ok(previous)  # caller must GET current state after a replay
    claim = db.session.get(S4AccountClaim, target.id)
    if action == "lock":
        if target.locked or claim:
            fail(409, "CONFLICT", "Existing lock must not be adopted.")
        db.session.add(S4AccountClaim(user_id=target.id, ticket_id=data["ticket_id"]))
    else:
        if not claim or claim.ticket_id != data["ticket_id"]:
            fail(409, "CONFLICT", "S4 lock ownership mismatch.")
        db.session.delete(claim)
    from ..auth import revoke_sessions
    changed = target.locked != (action == "lock")
    target.locked = action == "lock"
    revoked = revoke_sessions(target.id)
    db.session.flush()
    result = {**state(target), "changed": changed, "revoked_sessions": revoked}
    db.session.add(ResponseReceipt(request_key=key, fingerprint=fingerprint, result=result))
    db.session.commit()
    emit("auth.account_locked" if action == "lock" else "auth.account_unlocked", "success", 200,
         username=username, reason_code="s4_lab" if action == "lock" else "false_positive")
    return ok(result)
