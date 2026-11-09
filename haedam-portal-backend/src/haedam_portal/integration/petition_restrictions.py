"""H1: restrict only new petitions, bound to an exact ticket cycle."""
import re

from sqlalchemy import select

from ..common import body, fail, ok, text
from ..models import PetitionWriteRestriction, ResponseReceipt, User, db, iso, now
from . import bp, authenticate_response, replayed, request_digests
from .events import emit


def active_restriction(user_id):
    # Locking read sees the current committed row on MySQL even after session loading.
    return db.session.scalar(select(PetitionWriteRestriction).where(
        PetitionWriteRestriction.user_id == user_id,
        PetitionWriteRestriction.released_at.is_(None)).with_for_update())


@bp.get('/petitions/restrictions/<username>')
def restriction_status(username):
    authenticate_response()
    user = db.session.scalar(select(User).where(User.username == username))
    if user is None:
        fail(404, 'NOT_FOUND', '계정을 찾을 수 없습니다.')
    entry = active_restriction(user.id)
    return ok({'username': user.username, 'restricted': entry is not None,
               'ticket_id': entry.ticket_id if entry else None})


@bp.post('/petitions/<action>')
def restriction_action(action):
    authenticate_response()
    if action not in {'restrict', 'release'}:
        fail(404, 'NOT_FOUND', '존재하지 않는 대응입니다.')
    data = body()
    if set(data) != {'username', 'ticket_id'}:
        fail(400, 'VALIDATION_ERROR', 'username과 ticket_id만 입력해 주세요.')
    username = text(data, 'username', 3, 40, strip=False)
    if not re.fullmatch(r'[a-z0-9_]{3,40}', username):
        fail(400, 'VALIDATION_ERROR', '올바른 계정 ID가 필요합니다.')
    ticket_id = data['ticket_id']
    if not isinstance(ticket_id, str) or not re.fullmatch(r'T-[0-9]{8}-[0-9]{4}', ticket_id):
        fail(400, 'VALIDATION_ERROR', '올바른 티켓 ID가 필요합니다.')
    request_key, fingerprint = request_digests({'h1': action, 'username': username, 'ticket_id': ticket_id})
    user = db.session.scalar(select(User).where(User.username == username).with_for_update())
    if user is None:
        fail(404, 'NOT_FOUND', '계정을 찾을 수 없습니다.')
    previous = replayed(request_key, fingerprint)
    if previous:
        return ok(previous)  # Historical receipt; callers must also read current state.
    if action == 'restrict' and user.role != 'citizen':
        fail(403, 'FORBIDDEN', '시민 계정의 민원 작성만 제한할 수 있습니다.')
    entry = db.session.scalar(select(PetitionWriteRestriction).where(
        PetitionWriteRestriction.user_id == user.id,
        PetitionWriteRestriction.ticket_id == ticket_id).with_for_update())
    active = active_restriction(user.id)
    if active and active.ticket_id != ticket_id:
        fail(409, 'CONFLICT', '다른 티켓이 소유한 작성 제한입니다.')
    changed = False
    if action == 'restrict':
        if entry and entry.released_at is not None:
            fail(409, 'CONFLICT', '해제된 티켓으로 다시 제한할 수 없습니다.')
        if entry is None:
            entry = PetitionWriteRestriction(user_id=user.id, ticket_id=ticket_id, created_at=now())
            db.session.add(entry)
            changed = True
    else:
        if entry is None:
            fail(409, 'CONFLICT', '이 티켓의 작성 제한 기록이 없습니다.')
        if entry.released_at is None:
            entry.released_at = now()
            changed = True
    result = {'username': username, 'ticket_id': ticket_id, 'restricted': action == 'restrict',
              'changed': changed, 'changed_at': iso(entry.released_at or entry.created_at)}
    db.session.add(ResponseReceipt(request_key=request_key, fingerprint=fingerprint, result=result))
    db.session.commit()
    if changed:
        emit('petition.write_restricted' if action == 'restrict' else 'petition.write_released',
             'success', 200, username=username, ticket_id=ticket_id)
    return ok(result)
