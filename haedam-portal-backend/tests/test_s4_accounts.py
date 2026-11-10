"""Opt-in S4 authority, atomic claim and session revocation. Temporary SQLite only."""
import pytest
from sqlalchemy import select
from werkzeug.security import check_password_hash, generate_password_hash

from conftest import Actor, PASSWORD
from haedam_portal.models import db, User, LoginSession, S4AccountClaim

TARGET = 'zz_s4_target'
TICKET = 'T-20261110-0001'
RESPONSE_KEY = 'offline-response-' + 'a'*32
RELEASE_KEY = 'offline-release-' + 'b'*32


@pytest.fixture
def s4(app):
    app.config.update(S4_ENABLED=True, S4_ACCOUNT_ALLOWLIST=[TARGET], RESPONSE_API_KEY=RESPONSE_KEY,
                      S4_RELEASE_KEY=RELEASE_KEY)
    with app.app_context():
        user = User(username=TARGET, display_name='S4 synthetic', role='citizen', password_hash=generate_password_hash(PASSWORD))
        db.session.add(user); db.session.commit()
        user_id = user.id
    return app, user_id


def change(app, user_id, action='lock', ticket=TICKET, key=None, request_id=None, **kwargs):
    return app.test_client().post('/api/v1/response/s4/accounts/'+TARGET+'/'+action,
        json={'user_id': user_id, 'ticket_id': ticket, **({'reason_code': 'false_positive'} if action=='unlock' else {})},
        headers={'X-Response-Key': key or (RELEASE_KEY if action=='unlock' else RESPONSE_KEY),
                 'Idempotency-Key': request_id or f's4-{ticket}-{user_id}-{action}'}, **kwargs)


def status(app):
    return app.test_client().get('/api/v1/response/s4/accounts/'+TARGET, headers={'X-Response-Key': RESPONSE_KEY})


def test_lock_old_sessions_password_preserved_unlock_new_login(s4):
    app, uid = s4
    old1, old2, normal = Actor(app,TARGET), Actor(app,TARGET), Actor(app,'other')
    old_cookie = old1.client.get_cookie('haedam_session').value
    assert status(app).json['data']['active_sessions']==2
    locked = change(app,uid)
    assert locked.status_code==200 and locked.json['data']['revoked_sessions']==2
    assert status(app).json['data']=={'user_id':uid,'username':TARGET,'locked':True,'active_sessions':0,'owner_ticket_id':TICKET}
    assert old1.call('GET','/auth/me').json['data']['user'] is None
    assert old2.call('GET','/auth/me').json['data']['user'] is None
    anonymous = Actor(app)
    assert anonymous.call('POST','/auth/login',{'username':TARGET,'password':PASSWORD}).status_code==401
    assert normal.call('GET','/auth/me').json['data']['user']['username']=='other'
    assert change(app,uid,'unlock').status_code==200
    assert status(app).json['data']['owner_ticket_id'] is None
    stale = app.test_client(); stale.set_cookie('haedam_session',old_cookie)
    assert stale.get('/api/v1/auth/me').json['data']['user'] is None
    assert Actor(app,TARGET).call('GET','/auth/me').json['data']['user']['username']==TARGET
    with app.app_context():
        assert check_password_hash(db.session.get(User,uid).password_hash,PASSWORD)


def test_default_disabled_and_missing_or_reused_keys(s4):
    app,uid=s4
    for config in ({'S4_ENABLED':False},{'S4_RELEASE_KEY':''},{'S4_RELEASE_KEY':RESPONSE_KEY}):
        original={k:app.config[k] for k in config};app.config.update(config)
        assert change(app,uid).status_code==403 and status(app).status_code==403
        app.config.update(original)
    assert change(app,uid,key='wrong').status_code==403
    assert change(app,uid,key=RELEASE_KEY).status_code==403
    assert change(app,uid,'unlock',key=RESPONSE_KEY).status_code==403
    assert change(app,uid,environ_overrides={'REMOTE_ADDR':'198.51.100.20'}).status_code==403


def test_scope_admin_identity_and_exact_body(s4):
    app,uid=s4
    app.config['S4_ACCOUNT_ALLOWLIST']=[]
    assert change(app,uid).status_code==403
    app.config['S4_ACCOUNT_ALLOWLIST']=[TARGET]
    assert change(app,uid+100).status_code==409
    for data in ({'user_id':True,'ticket_id':TICKET}, {'user_id':uid,'ticket_id':TICKET,'new_password':'not-allowed'}):
        assert app.test_client().post('/api/v1/response/s4/accounts/'+TARGET+'/lock',json=data,
            headers={'X-Response-Key':RESPONSE_KEY,'Idempotency-Key':'offline-invalid'}).status_code==400
    with app.app_context():
        db.session.get(User,uid).role='admin';db.session.commit()
    assert change(app,uid).status_code==403 and status(app).status_code==403


def test_idempotency_conflict_ownership_and_external_lock(s4):
    app,uid=s4
    initial=change(app,uid)
    assert change(app,uid).json==initial.json
    assert change(app,uid,ticket='T-20261110-0002',request_id=f's4-{TICKET}-{uid}-lock').status_code==409
    assert change(app,uid,'unlock',ticket='T-20261110-0002').status_code==409
    assert status(app).json['data']['locked']
    released=change(app,uid,'unlock')
    assert change(app,uid,'unlock').json==released.json
    # A late duplicate lock receipt must not re-lock; current readback is authoritative.
    assert change(app,uid).status_code==200
    assert status(app).json['data']['locked'] is False
    with app.app_context():
        db.session.get(User,uid).locked=True;db.session.commit()
    assert change(app,uid,ticket='T-20261110-0002').status_code==409
    assert change(app,uid,'unlock',ticket='T-20261110-0002').status_code==409


def test_stale_release_receipt_does_not_release_new_ticket(s4):
    app,uid=s4
    assert change(app,uid).status_code==200
    assert change(app,uid,'unlock').status_code==200
    second='T-20261110-0002'
    assert change(app,uid,ticket=second).status_code==200
    assert change(app,uid,'unlock').status_code==200
    assert status(app).json['data']['owner_ticket_id']==second
    assert status(app).json['data']['locked']


def test_claim_and_lock_roll_back_on_receipt_failure(s4,monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError
    app,uid=s4
    original=db.session.commit
    def failed_commit():
        raise SQLAlchemyError('synthetic write failure')
    monkeypatch.setattr(db.session,'commit',failed_commit)
    assert change(app,uid).status_code==503
    monkeypatch.setattr(db.session,'commit',original)
    with app.app_context():
        assert db.session.get(S4AccountClaim,uid) is None
        assert db.session.get(User,uid).locked is False


@pytest.mark.parametrize('manual',[True,False])
def test_other_responder_supersedes_s4_claim(s4,manual):
    app,uid=s4
    assert change(app,uid).status_code==200
    if manual:
        assert Actor(app,'admin').call('PATCH',f'/admin/users/{uid}',{'locked':True}).status_code==200
    else:
        assert app.test_client().post(f'/api/v1/response/accounts/{uid}/lock',json={},
            headers={'X-Response-Key':RESPONSE_KEY,'Idempotency-Key':'separate-responder-lock'}).status_code==200
    assert status(app).json['data']['owner_ticket_id'] is None
    assert change(app,uid,'unlock').status_code==409
    assert status(app).json['data']['locked']


def test_generated_graph_trace_against_real_portal_and_ticket_sqlite(s4,tmp_path,monkeypatch):
    import sys
    from contextlib import closing
    from pathlib import Path
    from urllib.parse import urlsplit
    root=Path(__file__).resolve().parents[2]
    sys.path.insert(0,str(root/'tests'))
    sys.path.insert(0,str(root/'services/ticket-store'))
    from test_s4_workflows import S4Workflows
    from ticket_store.app import create_n8n_app
    from ticket_store import db as ticket_db
    monkeypatch.setattr(ticket_db,'now_iso',lambda:'2026-11-10T12:00:00+09:00')
    app,uid=s4
    Actor(app,TARGET); Actor(app,TARGET)
    normal=Actor(app,'other')
    S4Workflows.setUpClass(); model=S4Workflows()
    trace=model.run_graph([model.respond(),model.respond(),model.release(),
                           model.respond(body=model.body(event_id='next_cycle')),model.release()],
                          account={'user_id':uid,'username':TARGET,'locked':False,'active_sessions':2,'owner_ticket_id':None})
    ticket_path=str(tmp_path/'tickets.sqlite3');ticket_key='offline-ticket-key-'+ 'c'*32
    clients={'portal-response':app.test_client(),'ticket-store':create_n8n_app(ticket_path,ticket_key).test_client()}
    for call in trace['calls']:
        u=urlsplit(call['url'])
        key=ticket_key if u.hostname=='ticket-store' else RELEASE_KEY if u.path.endswith('/unlock') else RESPONSE_KEY
        response=clients[u.hostname].open(u.path+('?' + u.query if u.query else ''),method=call['method'],
            headers={**call['headers'],'X-Response-Key':key},json=call['body'] if call['method']=='POST' else None)
        assert response.status_code in (200,201), (u.path,response.json)
        if u.hostname=='portal-response' and u.path.endswith('/lock'):
            assert response.json['data']['locked'] and response.json['data']['active_sessions']==0
        if u.hostname=='portal-response' and u.path.endswith('/unlock'):
            assert not response.json['data']['locked'] and response.json['data']['owner_ticket_id'] is None
    with closing(ticket_db.connect(ticket_path)) as connection:
        assert ticket_db.dashboard_work(connection)['items']==[]
        assert [row[0] for row in connection.execute('SELECT status FROM tickets ORDER BY ticket_id')]==['closed','restored']
    assert not status(app).json['data']['locked']
    assert normal.call('GET','/auth/me').json['data']['user']['username']=='other'


def test_migration_from_previous_revision_preserves_account(tmp_path):
    from pathlib import Path
    from flask_migrate import upgrade
    from haedam_portal import create_app
    root=Path(__file__).resolve().parents[1]
    app=create_app({'TESTING':True,'SQLALCHEMY_DATABASE_URI':'sqlite:///'+(tmp_path/'migration.sqlite3').as_posix(),
                    'GELF_ENABLED':False,'EVENT_LOG_PATH':str(tmp_path/'events.jsonl')})
    with app.app_context():
        upgrade(directory=str(root/'migrations'),revision='91d4e218ac07')
        db.session.add(User(username='zz_preserved',display_name='synthetic',password_hash='synthetic-hash',locked=True))
        db.session.commit()
        upgrade(directory=str(root/'migrations'))
        assert db.session.scalar(select(User).where(User.username=='zz_preserved')).locked
        assert db.session.scalar(select(S4AccountClaim)) is None
        db.session.remove();db.engine.dispose()
