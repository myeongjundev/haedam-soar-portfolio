import hashlib
import re
import secrets
from datetime import timedelta

from flask import Blueprint, current_app, g, request
from sqlalchemy import delete, func, select
from werkzeug.security import check_password_hash, generate_password_hash

from ..common import body, client_ip, fail, ok, require, text
from ..models import LoginAttempt, LoginSession, User, db, now
from ..integration.events import emit

bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def load_session():
    g.user, g.login_session, g.new_cookie = None, None, None
    raw = request.cookies.get("haedam_session", "")
    if len(raw) > 128:
        return
    if raw:
        session = db.session.get(LoginSession, token_hash(raw))
        if session and session.expires_at > now():
            user = db.session.get(User, session.user_id) if session.user_id else None
            if session.user_id and (not user or user.locked):
                return
            g.login_session, g.user = session, user


def new_session(user=None):
    if g.login_session:
        db.session.delete(g.login_session)
    raw = secrets.token_urlsafe(32)
    session = LoginSession(token_hash=token_hash(raw), user_id=user.id if user else None,
                           csrf=secrets.token_urlsafe(32), expires_at=now() + timedelta(seconds=current_app.config["SESSION_TTL"]))
    db.session.add(session)
    db.session.execute(delete(LoginSession).where(LoginSession.expires_at <= now()))
    g.login_session, g.user, g.new_cookie = session, user, raw
    db.session.commit()
    return {"user": user.public() if user else None, "csrf_token": session.csrf}


def revoke_sessions(user_id):
    return db.session.execute(delete(LoginSession).where(LoginSession.user_id == user_id)).rowcount


def validate_user(data):
    username = text(data, "username", 3, 40).lower()
    if not re.fullmatch(r"[a-z0-9_]{3,40}", username):
        fail(400, "VALIDATION_ERROR", "아이디는 영문 소문자·숫자·밑줄 3~40자로 입력해 주세요.")
    name = text(data, "display_name", 2, 30)
    password = text(data, "password", 10, 128, strip=False)
    if db.session.scalar(select(User).where(User.username == username)):
        fail(409, "CONFLICT", "이미 사용 중인 아이디입니다.")
    return username, name, generate_password_hash(password)


@bp.get("/me")
def me():
    if not g.login_session:
        return ok(new_session())
    return ok({"user": g.user.public() if g.user else None, "csrf_token": g.login_session.csrf})


@bp.post("/register")
def register():
    if g.user:
        fail(409, "CONFLICT", "로그아웃 후 가입해 주세요.")
    username, name, password_hash = validate_user(body())
    user = User(username=username, display_name=name, password_hash=password_hash, role="citizen")
    db.session.add(user)
    db.session.commit()
    return ok(user.public(), 201)


@bp.post("/login")
def login():
    data = body()
    username = text(data, "username", 1, 40).lower()
    password = text(data, "password", 1, 128, strip=False)
    cutoff = now() - timedelta(minutes=5)
    db.session.execute(delete(LoginAttempt).where(LoginAttempt.created_at < cutoff))
    count = db.session.scalar(select(func.count()).select_from(LoginAttempt).where(LoginAttempt.src_ip == client_ip()))
    if count >= current_app.config["LOGIN_RATE_LIMIT"]:
        db.session.commit()
        emit("auth.login_failed", "denied", 429, username=username)
        fail(429, "RATE_LIMITED", "로그인 시도가 많습니다. 5분 후 다시 시도해 주세요.")
    user = db.session.scalar(select(User).where(User.username == username))
    # Unknown users still pay the password-hash verification cost.
    valid = check_password_hash(user.password_hash if user else current_app.config["DUMMY_PASSWORD_HASH"], password)
    if not user or not valid or user.locked:
        db.session.add(LoginAttempt(src_ip=client_ip()))
        db.session.commit()
        emit("auth.login_failed", "failure", 401, username=username)
        fail(401, "INVALID_CREDENTIALS", "아이디·비밀번호 또는 계정 이용 상태를 확인해 주세요.")
    result = new_session(user)
    emit("auth.login_succeeded", "success", 200, username=user.username)
    return ok(result)


@bp.post("/logout")
@require()
def logout():
    db.session.delete(g.login_session)
    db.session.commit()
    g.clear_cookie = True
    return ok({"logged_out": True})


@bp.post("/password")
@require()
def password():
    data = body()
    old = text(data, "current_password", 1, 128, strip=False)
    new = text(data, "new_password", 10, 128, strip=False)
    if not check_password_hash(g.user.password_hash, old):
        fail(400, "VALIDATION_ERROR", "현재 비밀번호가 일치하지 않습니다.")
    if old == new:
        fail(400, "VALIDATION_ERROR", "새 비밀번호는 현재 비밀번호와 달라야 합니다.")
    user = g.user
    user.password_hash = generate_password_hash(new)
    revoke_sessions(user.id)
    g.login_session = None
    result = new_session(user)
    emit("auth.password_reset", "success", 200, username=user.username)
    return ok(result)
