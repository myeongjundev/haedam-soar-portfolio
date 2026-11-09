import json
from pathlib import Path

from conftest import Actor
from test_ip_block_and_file_key import respond, events

PETITION = {'title': '합성 민원 제목입니다', 'content': '검증용 합성 민원 내용입니다.', 'category': '기타'}
TICKET = 'T-20261109-0001'


def action(app, name, key, username='citizen', ticket=TICKET):
    return respond(app, 'POST', '/petitions/' + name,
                   {'username': username, 'ticket_id': ticket}, key=key)


def test_write_only_restriction_keeps_session_read_and_same_ip_other_citizen(app, actors):
    citizen, other = actors['citizen'], actors['other']
    first = citizen.call('POST', '/petitions', PETITION)
    assert first.status_code == 201
    assert action(app, 'restrict', 'h1-restrict-001').json['data']['restricted']
    denied = citizen.call('POST', '/petitions', PETITION)
    assert denied.status_code == 429 and denied.json['error']['code'] == 'PETITION_WRITE_RESTRICTED'
    assert citizen.call('GET', '/petitions/' + str(first.json['data']['id'])).status_code == 200
    assert citizen.call('GET', '/auth/me').json['data']['user']['username'] == 'citizen'
    assert Actor(app, 'citizen').call('POST', '/petitions', PETITION).status_code == 429
    assert other.call('POST', '/petitions', PETITION).status_code == 201
    assert action(app, 'release', 'h1-release-001').json['data']['restricted'] is False
    assert citizen.call('POST', '/petitions', PETITION).status_code == 201
    assert respond(app, 'GET', '/petitions/restrictions/citizen').json['data']['restricted'] is False
    observed = events(app)
    assert len([e for e in observed if e['event_type'] == 'petition.write_restricted']) == 1
    assert len([e for e in observed if e['event_type'] == 'petition.write_released']) == 1
    assert len([e for e in observed if e['event_type'] == 'petition.write_denied']) == 2
    assert '검증용 합성 민원 내용' not in Path(app.config['EVENT_LOG_PATH']).read_text(encoding='utf-8')


def test_ownership_replay_and_old_ticket_cannot_restrict_or_release_new_cycle(app, actors):
    first = action(app, 'restrict', 'h1-owner-001')
    assert action(app, 'restrict', 'h1-owner-001').json == first.json
    assert action(app, 'restrict', 'h1-owner-001', username='other').status_code == 409
    assert action(app, 'restrict', 'h1-other-owner', ticket='T-20261109-0002').status_code == 409
    assert action(app, 'release', 'h1-wrong-owner', ticket='T-20261109-0002').status_code == 409
    assert action(app, 'release', 'h1-owner-release').status_code == 200
    assert action(app, 'release', 'h1-owner-release-again').json['data']['changed'] is False
    assert action(app, 'restrict', 'h1-stale-new-key').status_code == 409
    assert action(app, 'restrict', 'h1-owner-001').json == first.json  # historical result only
    assert respond(app, 'GET', '/petitions/restrictions/citizen').json['data']['restricted'] is False
    assert action(app, 'restrict', 'h1-new-cycle', ticket='T-20261109-0002').status_code == 200
    assert action(app, 'release', 'h1-stale-release').status_code == 409
    assert actors['citizen'].call('POST', '/petitions', PETITION).status_code == 429


def test_response_boundaries_and_validation(app):
    for role in ('staff', 'admin'):
        assert action(app, 'restrict', 'h1-role-' + role, username=role).status_code == 403
    assert action(app, 'restrict', 'h1-no-account', username='absent').status_code == 404
    assert action(app, 'restrict', 'h1-invalid-ticket', ticket='bad').status_code == 400
    data = {'username': 'citizen', 'ticket_id': TICKET}
    assert respond(app, 'POST', '/petitions/restrict', data, key='h1-outside-cidr', addr='192.0.2.20').status_code == 403
    assert app.test_client().post('/api/v1/response/petitions/restrict', json=data).status_code == 403
    assert respond(app, 'POST', '/petitions/restrict', {**data, 'extra': True}, key='h1-extra-field').status_code == 400
    assert action(app, 'release', 'h1-never-owned').status_code == 409


def test_mysql_concurrent_owners_only_one_can_restrict(app):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    import pytest
    from haedam_portal.models import db
    with app.app_context():
        if db.engine.dialect.name != 'mysql':
            pytest.skip('MySQL row locks; run tools/check_mysql.py')
    gate = Barrier(2)
    def restrict(number):
        gate.wait(timeout=10)
        response = action(app, 'restrict', 'concurrent-owner-' + str(number), ticket=f'T-20261109-000{number}')
        return response.status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(restrict, (1, 2))) == [200, 409]


def test_mysql_write_waiting_on_account_lock_observes_new_restriction(app, actors):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    import pytest
    from sqlalchemy import event, select
    from haedam_portal.models import User, PetitionWriteRestriction, db
    with app.app_context():
        if db.engine.dialect.name != 'mysql':
            pytest.skip('MySQL snapshot regression; run tools/check_mysql.py')
        engine = db.engine
        user_id = db.session.scalar(select(User.id).where(User.username == 'citizen'))
    waiting = Event()
    def before_lock(conn, cursor, statement, params, context, executemany):
        if 'FOR UPDATE' in statement and 'users.id' in statement and 'petition_write_restrictions' not in statement:
            waiting.set()
    event.listen(engine, 'before_cursor_execute', before_lock)
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            connection.execute(select(User.id).where(User.id == user_id).with_for_update())
            waiting.clear()
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(actors['citizen'].call, 'POST', '/petitions', PETITION)
                try:
                    assert waiting.wait(10), 'write did not reach shared account lock'
                    connection.execute(PetitionWriteRestriction.__table__.insert().values(user_id=user_id, ticket_id=TICKET))
                    transaction.commit()
                finally:
                    if transaction.is_active:
                        transaction.rollback()
                assert pending.result(timeout=10).status_code == 429
    finally:
        event.remove(engine, 'before_cursor_execute', before_lock)
