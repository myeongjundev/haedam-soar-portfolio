from flask import Blueprint, g, request
from sqlalchemy import func, select
from werkzeug.security import generate_password_hash

from ..auth import revoke_sessions, validate_user
from ..common import body, fail, ok, pagination, require, text
from ..integration.events import emit
from ..models import User, db

bp = Blueprint("admin", __name__, url_prefix="/api/v1/admin/users")


def locked_user(user_id):
    # Serialize administrator role/lock updates in a stable order on MySQL.
    users = db.session.scalars(select(User).order_by(User.id).with_for_update()).all()
    target = next((u for u in users if u.id == user_id), None)
    if not target:
        fail(404, "NOT_FOUND", "계정을 찾을 수 없습니다.")
    if target.id == g.user.id:
        fail(409, "CONFLICT", "본인 계정은 이 화면에서 변경할 수 없습니다.")
    return target, users


@bp.get("")
@require("admin")
def users():
    page, size = pagination()
    role = request.args.get("role", "")
    locked = request.args.get("locked", "")
    if (len(request.args.getlist("role")) > 1 or len(request.args.getlist("locked")) > 1
            or role not in {"", "citizen", "staff", "admin"} or locked not in {"", "true", "false"}):
        fail(400, "VALIDATION_ERROR", "계정 권한·이용 상태 조건을 확인해 주세요.")
    query = select(User)
    q = request.args.get("q", "").strip()[:40]
    if q:
        query = query.where(User.username.contains(q, autoescape=True) | User.display_name.contains(q, autoescape=True))
    # Search-wide facets are independent of pagination and role/lock selection.
    matched = query.subquery()
    groups = db.session.execute(select(matched.c.role, matched.c.locked, func.count())
                                .group_by(matched.c.role, matched.c.locked)).all()
    summary = {"scope": "search", "total": 0, "roles": {"citizen": 0, "staff": 0, "admin": 0},
               "locked": 0, "unlocked": 0}
    total = 0
    for group_role, group_locked, count in groups:
        summary["total"] += count
        summary["roles"][group_role] += count
        summary["locked" if group_locked else "unlocked"] += count
        if (not role or group_role == role) and (not locked or group_locked == (locked == "true")):
            total += count
    if role:
        query = query.where(User.role == role)
    if locked:
        query = query.where(User.locked.is_(locked == "true"))
    items = db.session.scalars(query.order_by(User.id).offset((page-1)*size).limit(size)).all()
    return ok({"items": [u.public() for u in items], "total": total, "page": page,
               "page_size": size, "pages": max(1, (total+size-1)//size), "summary": summary})


@bp.post("")
@require("admin")
def create_user():
    data = body()
    username, name, hashed = validate_user(data)
    role = data.get("role")
    if role not in {"citizen", "staff", "admin"}:
        fail(400, "VALIDATION_ERROR", "권한을 선택해 주세요.")
    department = text(data, "department", 0, 40) if "department" in data else "민원행정과" if role == "staff" else ""
    user = User(username=username, display_name=name, password_hash=hashed, role=role, department=department)
    db.session.add(user)
    db.session.commit()
    return ok(user.public(), 201)


@bp.patch("/<int:user_id>")
@require("admin")
def change_user(user_id):
    data = body()
    if not data or set(data) - {"role", "locked"}:
        fail(400, "VALIDATION_ERROR", "권한 또는 잠금 상태를 입력해 주세요.")
    target, all_users = locked_user(user_id)
    previous = target.role
    role = data.get("role", previous)
    if role not in {"citizen", "staff", "admin"} or ("locked" in data and data["locked"] is not True):
        fail(400, "VALIDATION_ERROR", "잠금 해제는 비밀번호 재설정을 사용해 주세요.")
    will_lock = data.get("locked", target.locked)
    if target.role == "admin" and (role != "admin" or will_lock):
        if not any(u.id != target.id and u.role == "admin" and not u.locked for u in all_users):
            fail(409, "CONFLICT", "마지막 관리자는 잠그거나 강등할 수 없습니다.")
    # Do not strand petitions assigned to a staff member being demoted.
    if target.role == "staff" and role != "staff":
        from ..models import Petition
        if db.session.scalar(select(Petition.id).where(Petition.assignee_id == target.id, Petition.status != "completed").limit(1)):
            fail(409, "CONFLICT", "담당 민원을 모두 처리한 뒤 권한을 변경해 주세요.")
    target.role, target.locked = role, will_lock
    revoke_sessions(target.id)
    db.session.commit()
    if previous != role:
        emit("iam.role_changed", "success", 200, username=target.username, previous_role=previous, new_role=role)
    if will_lock:
        emit("auth.account_locked", "success", 200, username=target.username)
    return ok(target.public())


@bp.post("/<int:user_id>/unlock")
@require("admin")
def unlock_user(user_id):
    # S4 오탐 확인 시 비밀번호를 유지한 채 잠금만 푼다(B 정책, 10/22). 탈취 의심은 reset-password를 쓴다.
    data = body()
    reason = text(data, "reason_code", 1, 40)
    if reason != "false_positive":
        fail(400, "VALIDATION_ERROR", "해제 사유 코드가 올바르지 않습니다.")
    target, _ = locked_user(user_id)
    if not target.locked:
        # 잠기지 않은 계정은 바꾸지 않는다: 정상 세션 유지, 이벤트 없음.
        db.session.commit()
        return ok(target.public())
    target.locked = False  # 비밀번호 유지. 회수된 세션은 복원하지 않아 새 로그인을 요구한다.
    revoke_sessions(target.id)
    db.session.commit()
    # 실제 잠금→해제일 때만 남는다. 처리자는 요청이 아니라 인증된 g.user에서 가져온다.
    emit("auth.account_unlocked", "success", 200, username=target.username,
         actor_user_id=g.user.id, actor_username=g.user.username, reason_code=reason)
    return ok(target.public())


@bp.post("/<int:user_id>/reset-password")
@require("admin")
def reset_password(user_id):
    data = body()
    new = text(data, "new_password", 10, 128, strip=False)
    target, _ = locked_user(user_id)
    target.password_hash = generate_password_hash(new)
    target.locked = False
    revoke_sessions(target.id)
    db.session.commit()
    emit("auth.password_reset", "success", 200, username=target.username)
    return ok(target.public())
