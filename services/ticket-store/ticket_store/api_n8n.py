"""n8n check/record API (192.0.2.3:8088, X-Response-Key required). Design section 3."""
from contextlib import closing
import hmac

from flask import Blueprint, current_app, jsonify, request

from . import core, validate

bp = Blueprint("api_n8n", __name__, url_prefix="/api/v1/tickets")


def error(status, code, message):
    return jsonify(ok=False, error={"code": code, "message": message}), status


@bp.before_request
def require_key():
    given = request.headers.get("X-Response-Key", "")
    if not hmac.compare_digest(given.encode(), current_app.config["TICKET_STORE_KEY"].encode()):
        return error(401, "UNAUTHORIZED", "X-Response-Key is missing or wrong")
    return None


def conn():
    return closing(current_app.extensions["ticket_store_conn"]())


def _valid_text(value):
    return bool(value) and len(value) <= 300 and validate.NO_CONTROL.match(value) is not None


@bp.get("/open")
def check():
    """?seat=&group_key= (one seat), ?group_key= (all seats) or ?target= (all seats, release hold)."""
    group_key, seat, target = (request.args.get(name) or None for name in ("group_key", "seat", "target"))
    if target is not None:
        if group_key is not None or seat is not None or not _valid_text(target):
            return error(400, "VALIDATION_ERROR", "target must be used alone and be valid")
        with conn() as c:
            return jsonify(core.check_target(c, target))
    if not _valid_text(group_key or ""):
        return error(400, "VALIDATION_ERROR", "group_key is invalid")
    if seat is not None and seat not in validate.SEATS:
        return error(400, "VALIDATION_ERROR", "seat must be one of A, B, C, D")
    with conn() as c:
        return jsonify(core.check(c, group_key, seat))


@bp.get("/active")
def active():
    try:
        resource = validate.resource_query(request.args)
    except validate.Invalid as exc:
        return error(400, "VALIDATION_ERROR", str(exc))
    with conn() as c:
        # Keep the ticket and action reads in one SQLite snapshot.
        c.execute("BEGIN")
        return jsonify(core.active_for_resource(c, resource))


@bp.post("/record")
def record():
    try:
        validate.idempotency_key(request.headers.get("Idempotency-Key"))
        body = request.get_json(silent=True)
        validate.record_body(body)
    except validate.Invalid as exc:
        return error(400, "VALIDATION_ERROR", str(exc))
    with conn() as c:
        try:
            status, response = core.record(c, body, request.headers["Idempotency-Key"])
        except core.Conflict:
            return error(409, "IDEMPOTENCY_CONFLICT", "Idempotency-Key was used with a different body")
        except core.NoActionToUpdate:
            return error(400, "VALIDATION_ERROR", "effect/released stage has no matching active bot, via, action and target")
        except core.InvalidTransition as exc:
            return error(409, "INVALID_TRANSITION", str(exc))
        except core.StaleEffect:
            return error(409, "STALE_EFFECT", "effect_verified_at is earlier than the active action")
    return jsonify(response), status
