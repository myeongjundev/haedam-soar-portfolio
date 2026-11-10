import secrets

import click
from flask import current_app
from sqlalchemy import select
from werkzeug.security import generate_password_hash

from .models import Petition, PetitionHistory, User, db


def register_cli(app):
    @app.cli.command("create-admin")
    @click.option("--username", prompt="관리자 아이디")
    @click.option("--name", prompt="표시 이름")
    @click.password_option(confirmation_prompt=True)
    def create_admin(username, name, password):
        import re
        if not re.fullmatch(r"[a-z0-9_]{3,40}", username) or not 2 <= len(name) <= 30 or not 10 <= len(password) <= 128:
            raise click.ClickException("아이디·이름·비밀번호 길이/형식을 확인하세요.")
        if db.session.scalar(select(User).where(User.username == username)):
            raise click.ClickException("이미 존재하는 계정입니다.")
        db.session.add(User(username=username, display_name=name, password_hash=generate_password_hash(password), role="admin"))
        db.session.commit()
        click.echo("관리자 계정을 만들었습니다. 비밀번호는 기록하지 않았습니다.")

    @app.cli.command("seed-demo")
    @click.option("--confirm", is_flag=True, help="격리된 합성 데모 데이터임을 확인")
    def seed_demo(confirm):
        if not confirm:
            raise click.ClickException("합성 데이터 전용입니다. --confirm이 필요합니다.")
        if db.session.scalar(select(User.id).limit(1)):
            raise click.ClickException("빈 DB에서만 실행합니다. 기존 데이터를 삭제하지 않습니다.")
        password = secrets.token_urlsafe(14)
        users = [User(username="citizen_demo", display_name="김해담", password_hash=generate_password_hash(password), role="citizen"),
                 User(username="staff_demo", display_name="이담당", password_hash=generate_password_hash(password), role="staff", department="민원행정과"),
                 User(username="admin_demo", display_name="박관리", password_hash=generate_password_hash(password), role="admin")]
        db.session.add_all(users)
        db.session.flush()
        samples = [("해담로 보행로 가로등 점검 요청", "해담로 12번길 보행로의 가로등이 켜지지 않습니다. 안전한 귀가를 위해 점검을 부탁드립니다.", "안전·시설", "received", ""),
                   ("중앙공원 산책로 정비 요청", "중앙공원 동쪽 산책로의 보도블록이 들떠 있습니다. 통행 불편이 있어 정비를 요청합니다.", "공원·녹지", "in_progress", ""),
                   ("분리수거 안내 표지 정비 요청", "해담동 공동 분리수거장의 안내 표지가 낡아 알아보기 어렵습니다. 새 안내판 설치를 요청합니다.", "환경·청소", "completed", "요청하신 안내 표지 교체를 완료했습니다. 깨끗한 생활 환경을 위해 의견을 주셔서 감사합니다.")]
        for title, content, category, status, reply in samples:
            petition = Petition(title=title, content=content, category=category, status=status, reply=reply,
                                applicant_id=users[0].id, assignee_id=users[1].id if status != "received" else None)
            db.session.add(petition)
            db.session.flush()
            db.session.add(PetitionHistory(petition_id=petition.id, actor_id=users[0].id, to_status="received"))
            if status != "received":
                db.session.add(PetitionHistory(petition_id=petition.id, actor_id=users[1].id, from_status="received", to_status="in_progress"))
            if status == "completed":
                db.session.add(PetitionHistory(petition_id=petition.id, actor_id=users[1].id, from_status="in_progress", to_status="completed"))
        db.session.commit()
        click.echo("합성 계정: citizen_demo / staff_demo / admin_demo")
        click.echo("이번 로컬 데모의 공통 임시 비밀번호: " + password)
        click.echo("비밀번호는 Git·로그에 저장하지 말고 필요하면 계정 화면에서 변경하세요.")
