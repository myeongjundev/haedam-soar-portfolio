import hashlib
import hmac
import ipaddress
import json
from datetime import timedelta

from flask import Blueprint, current_app, request
from sqlalchemy import delete, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import StaleDataError
from werkzeug.security import generate_password_hash

from ..common import body, client_ip, fail, normalize_ip, ok, text
from ..models import BlockedIp, ResponseReceipt, User, db, iso, now
from .events import emit

bp = Blueprint("response", __name__, url_prefix="/api/v1/response")


def in_response_networks(ip):
    try:
        return any(ipaddress.ip_address(ip) in ipaddress.ip_network(net)
                   for net in current_app.config.get("RESPONSE_ALLOWED_CIDRS", []))
    except ValueError:
        return False


def authenticate_response():
    expected = current_app.config.get("RESPONSE_API_KEY", "")
    supplied = request.headers.get("X-Response-Key", "")
    if not expected or not in_response_networks(client_ip()) or not hmac.compare_digest(supplied, expected):
        fail(403, "FORBIDDEN", "대응 API 호출이 허용되지 않았습니다.")


def request_digests(scope):
    key = request.headers.get("Idempotency-Key", "")
    if not 8 <= len(key) <= 100:
        fail(400, "VALIDATION_ERROR", "Idempotency-Key는 8~100자가 필요합니다.")
    # Keyed digest prevents offline dictionary recovery of reset passwords.
    secret = current_app.config["RESPONSE_API_KEY"].encode()
    digest = lambda value: hmac.new(secret, value.encode(), hashlib.sha256).hexdigest()
    return digest(key), digest(json.dumps(scope, sort_keys=True))


def replayed(request_key, fingerprint):
    receipt = db.session.get(ResponseReceipt, request_key)
    if receipt and receipt.fingerprint != fingerprint:
        fail(409, "CONFLICT", "이 중복 방지 키는 다른 요청에 사용됐습니다.")
    return receipt.result if receipt else None


def ip_blocked(ip):
    if in_response_networks(ip):
        return False  # the response network is never refused, even by a stale row
    # Own short connection: a read in the request session here would pin the MySQL snapshot
    # before the response API's row lock, and concurrent replays would miss the committed receipt.
    with db.engine.connect() as connection:
        row = connection.execute(select(BlockedIp.expires_at).where(BlockedIp.ip == ip)).first()
    return row is not None and (row.expires_at is None or row.expires_at > now())


@bp.post("/accounts/<int:user_id>/<action>")
def account_response(user_id, action):
    authenticate_response()
    if action not in {"lock", "reset"}:
        fail(404, "NOT_FOUND", "존재하지 않는 대응입니다.")
    data = body()
    return account_action(User.id == user_id, {"id": user_id, "action": action, "data": data}, action, data)


@bp.post("/accounts/lock")
def account_lock_by_username():
    # S4 events carry only the username. Unlocking (reset) stays a person's call by id.
    authenticate_response()
    data = body()
    username = text(data, "username", 1, 40).lower()  # the same lookup as login
    return account_action(User.username == username, {"username": username, "action": "lock", "data": data}, "lock", data)


def account_action(target_filter, scope, action, data):
    request_key, fingerprint = request_digests(scope)
    # Lock the account before the first consistent read. Concurrent requests for
    # that target then see the committed receipt instead of a stale MySQL snapshot.
    target = db.session.scalar(select(User).where(target_filter).with_for_update())
    if not target:
        fail(404, "NOT_FOUND", "계정을 찾을 수 없습니다.")
    previous = replayed(request_key, fingerprint)
    if previous:
        return ok(previous)
    if target.role == "admin":
        fail(403, "FORBIDDEN", "관리자 계정은 자동 대응 대상에서 제외합니다.")
    from ..auth import revoke_sessions
    changed = not target.locked if action == "lock" else True
    if action == "reset":
        target.password_hash = generate_password_hash(text(data, "new_password", 10, 128, strip=False))
    target.locked = action == "lock"
    revoked = revoke_sessions(target.id)
    result = {"user_id": target.id, "locked": target.locked, "changed": changed, "revoked_sessions": revoked}
    db.session.add(ResponseReceipt(request_key=request_key, fingerprint=fingerprint, result=result))
    db.session.commit()
    emit("auth.account_locked" if action == "lock" else "auth.password_reset", "success", 200, username=target.username)
    return ok(result)


@bp.get("/ips")
def blocked_ips():
    authenticate_response()
    entries = db.session.scalars(select(BlockedIp).order_by(BlockedIp.ip))
    return ok({"items": [entry.public() for entry in entries if entry.active()]})


@bp.post("/ips/<action>")
def ip_response(action):
    authenticate_response()
    if action not in {"block", "unblock"}:
        fail(404, "NOT_FOUND", "존재하지 않는 대응입니다.")
    data = body()
    try:
        ip = normalize_ip(data.get("ip") if isinstance(data.get("ip"), str) else "")
    except ValueError:
        fail(400, "VALIDATION_ERROR", "IP 주소를 확인해 주세요.")
    minutes = data.get("minutes")
    if minutes is not None and (action != "block" or type(minutes) is not int or not 1 <= minutes <= 1440):
        fail(400, "VALIDATION_ERROR", "차단 시간은 차단할 때만 1~1440분 정수로 입력해 주세요.")
    if action == "block" and in_response_networks(ip):
        fail(403, "FORBIDDEN", "관리망·대응 호출자 주소는 차단할 수 없습니다.")
    request_key, fingerprint = request_digests({"ip": ip, "action": action, "data": data})
    for _ in range(3):
        try:
            result, applied = apply_ip_action(action, ip, minutes, request_key, fingerprint)
            break
        except (IntegrityError, StaleDataError):
            # Another request changed this address or used this key and committed first.
            # A fresh transaction sees that commit, so the retry replays or recomputes.
            db.session.rollback()
    else:
        fail(409, "CONFLICT", "같은 주소에 대한 요청이 겹쳤습니다. 같은 Idempotency-Key로 다시 보내 주세요.")
    if applied:
        emit("web.ip_blocked" if action == "block" else "web.ip_unblocked", "success", 200, target_ip=ip)
    return ok(result)


def apply_ip_action(action, ip, minutes, request_key, fingerprint):
    previous = replayed(request_key, fingerprint)
    if previous:
        return previous, False
    blocked = action == "block"
    if blocked:
        # Overlapping blocks keep the longer one (no expiry first), so a later request never cuts a
        # block short. Whole seconds: MySQL DATETIME then stores exactly what "changed" reports.
        until = (now() + timedelta(minutes=minutes)).replace(microsecond=0) if minutes else None
        entry = db.session.get(BlockedIp, ip)
        if entry is None:
            db.session.add(BlockedIp(ip=ip, expires_at=until))
            changed, kept = True, until
        elif entry.expires_at is None or (until is not None and entry.expires_at >= until):
            changed, kept = False, entry.expires_at
        else:
            # Re-checked on the latest committed row: if another request lengthened or removed the
            # block meanwhile, nothing is written and the retry recomputes from that commit.
            shorter = BlockedIp.expires_at.is_not(None) if until is None else BlockedIp.expires_at < until
            if db.session.execute(update(BlockedIp).where(BlockedIp.ip == ip, shorter).values(expires_at=until)).rowcount != 1:
                raise StaleDataError("blocked_ips row changed concurrently")
            changed, kept = True, until
        expires_at = iso(kept)
    else:
        # DELETE reads the latest committed row, so "changed" stays right when unblocks race.
        active = or_(BlockedIp.expires_at.is_(None), BlockedIp.expires_at > now())
        changed = db.session.execute(delete(BlockedIp).where(BlockedIp.ip == ip, active)).rowcount == 1
        db.session.execute(delete(BlockedIp).where(BlockedIp.ip == ip))
        expires_at = None
    result = {"ip": ip, "blocked": blocked, "changed": changed, "expires_at": expires_at}
    db.session.add(ResponseReceipt(request_key=request_key, fingerprint=fingerprint, result=result))
    db.session.commit()
    return result, True
