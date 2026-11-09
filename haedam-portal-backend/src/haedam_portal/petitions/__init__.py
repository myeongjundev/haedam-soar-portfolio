from flask import Blueprint, g, request
from sqlalchemy import func, or_, select
from sqlalchemy.orm.exc import StaleDataError

from ..common import body, fail, ok, pagination, require, text
from ..models import Petition, PetitionHistory, db
from ..integration.events import emit

CATEGORIES = ["도로·교통", "환경·청소", "공원·녹지", "안전·시설", "생활·복지", "기타"]
STATUSES = {"received", "in_progress", "completed"}
bp = Blueprint("petitions", __name__, url_prefix="/api/v1/petitions")


def scope():
    if g.user.role == "citizen":
        return Petition.applicant_id == g.user.id
    return or_(Petition.assignee_id.is_(None), Petition.assignee_id == g.user.id)


def get_petition(petition_id):
    petition = db.session.scalar(select(Petition).where(Petition.id == petition_id, scope()))
    if petition is None:
        fail(404, "NOT_FOUND", "요청한 민원을 찾을 수 없습니다.")
    return petition


@bp.get("")
@require("citizen", "staff")
def listing():
    page, size = pagination()
    query = select(Petition).where(scope())
    status = request.args.get("status", "")
    category = request.args.get("category", "")
    q = request.args.get("q", "").strip()[:100]
    if status:
        if status not in STATUSES:
            fail(400, "VALIDATION_ERROR", "민원 상태가 올바르지 않습니다.")
        query = query.where(Petition.status == status)
    if category:
        if category not in CATEGORIES:
            fail(400, "VALIDATION_ERROR", "민원 분야가 올바르지 않습니다.")
        query = query.where(Petition.category == category)
    if q:
        query = query.where(Petition.title.contains(q, autoescape=True))
    total = db.session.scalar(select(func.count()).select_from(query.subquery()))
    items = db.session.scalars(query.order_by(Petition.created_at.desc(), Petition.id.desc()).offset((page-1)*size).limit(size)).all()
    counts = dict(db.session.execute(select(Petition.status, func.count()).where(scope()).group_by(Petition.status)).all())
    return ok({"items": [p.public() for p in items], "total": total, "page": page,
               "page_size": size, "pages": max(1, (total+size-1)//size), "counts": counts})


@bp.post("")
@require("citizen")
def create():
    data = body()
    title = text(data, "title", 5, 120)
    content = text(data, "content", 10, 5000)
    category = data.get("category")
    if category not in CATEGORIES:
        fail(400, "VALIDATION_ERROR", "민원 분야를 선택해 주세요.", {"category": "민원 분야를 선택해 주세요."})
    petition = Petition(title=title, content=content, category=category, applicant_id=g.user.id)
    db.session.add(petition)
    db.session.flush()
    db.session.add(PetitionHistory(petition_id=petition.id, actor_id=g.user.id, to_status="received"))
    db.session.commit()
    emit("petition.created", "success", 201, username=g.user.username)
    return ok(petition.public(True), 201)


@bp.get("/<int:petition_id>")
@require("citizen", "staff")
def detail(petition_id):
    return ok(get_petition(petition_id).public(True))


@bp.patch("/<int:petition_id>/assignment")
@require("staff")
def assign(petition_id):
    body()
    petition = get_petition(petition_id)
    if petition.assignee_id is None:
        petition.assignee_id = g.user.id
        db.session.add(PetitionHistory(petition_id=petition.id, actor_id=g.user.id,
                                      from_status=petition.status, to_status=petition.status))
        try:
            db.session.commit()
        except StaleDataError:
            db.session.rollback()
            fail(409, "CONFLICT", "다른 담당자가 먼저 배정했습니다. 새로고침해 주세요.")
        emit("petition.updated", "success", 200, username=g.user.username)
    return ok(petition.public(True))


@bp.patch("/<int:petition_id>/status")
@require("staff")
def update(petition_id):
    petition = get_petition(petition_id)
    if petition.assignee_id != g.user.id:
        fail(403, "FORBIDDEN", "먼저 민원을 본인에게 배정해 주세요.")
    data = body()
    if type(data.get("version")) is not int or data["version"] != petition.version:
        fail(409, "CONFLICT", "민원이 변경됐습니다. 새로고침 후 다시 처리해 주세요.")
    target = data.get("status")
    allowed = {"received": "in_progress", "in_progress": "completed"}
    if allowed.get(petition.status) != target:
        fail(409, "CONFLICT", "접수 → 처리 중 → 완료 순서로 처리해 주세요.")
    reply = text(data, "reply", 10, 3000) if target == "completed" else ""
    previous = petition.status
    petition.status, petition.reply = target, reply
    db.session.add(PetitionHistory(petition_id=petition.id, actor_id=g.user.id, from_status=previous, to_status=target))
    try:
        db.session.commit()
    except StaleDataError:
        db.session.rollback()
        fail(409, "CONFLICT", "다른 요청이 먼저 처리했습니다. 새로고침해 주세요.")
    emit("petition.updated", "success", 200, username=g.user.username)
    return ok(petition.public(True))
