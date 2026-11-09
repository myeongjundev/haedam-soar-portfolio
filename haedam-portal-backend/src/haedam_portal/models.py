from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData

db = SQLAlchemy(metadata=MetaData(naming_convention={
    "ix": "ix_%(column_0_label)s", "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s", "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}))


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(value):
    return value.isoformat(timespec="seconds") + "Z" if value else None


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    display_name = db.Column(db.String(30), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(12), nullable=False, default="citizen")
    department = db.Column(db.String(40), nullable=False, default="")
    locked = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now)

    def public(self):
        return {"id": self.id, "username": self.username, "display_name": self.display_name,
                "role": self.role, "department": self.department, "locked": self.locked,
                "created_at": iso(self.created_at)}


class LoginSession(db.Model):
    __tablename__ = "login_sessions"
    token_hash = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    csrf = db.Column(db.String(64), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)


class Petition(db.Model):
    __tablename__ = "petitions"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(30), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="received")
    applicant_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    reply = db.Column(db.Text, nullable=False, default="")
    version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=now)
    updated_at = db.Column(db.DateTime, nullable=False, default=now, onupdate=now)
    applicant = db.relationship(User, foreign_keys=[applicant_id])
    assignee = db.relationship(User, foreign_keys=[assignee_id])
    __mapper_args__ = {"version_id_col": version}

    def public(self, detail=False):
        result = {"id": self.id, "reference": f"HD-{self.created_at.year}-{self.id:05d}",
                  "title": self.title, "category": self.category, "status": self.status,
                  "version": self.version, "created_at": iso(self.created_at), "updated_at": iso(self.updated_at),
                  "applicant": {"id": self.applicant.id, "display_name": self.applicant.display_name},
                  "assignee": {"id": self.assignee.id, "display_name": self.assignee.display_name} if self.assignee else None}
        if detail:
            result.update(content=self.content, reply=self.reply, history=[h.public() for h in self.history])
        return result


class PetitionHistory(db.Model):
    __tablename__ = "petition_history"
    id = db.Column(db.Integer, primary_key=True)
    petition_id = db.Column(db.Integer, db.ForeignKey("petitions.id"), nullable=False, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    from_status = db.Column(db.String(20))
    to_status = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now)
    petition = db.relationship(Petition, backref=db.backref("history", order_by="PetitionHistory.id", lazy="selectin"))
    actor = db.relationship(User)

    def public(self):
        return {"from_status": self.from_status, "to_status": self.to_status,
                "actor": self.actor.display_name, "created_at": iso(self.created_at)}


class ResponseReceipt(db.Model):
    __tablename__ = "response_receipts"
    request_key = db.Column(db.String(64), primary_key=True)
    fingerprint = db.Column(db.String(64), nullable=False)
    result = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now)


class BlockedIp(db.Model):
    __tablename__ = "blocked_ips"
    ip = db.Column(db.String(45), primary_key=True)
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=now)

    def active(self):
        return self.expires_at is None or self.expires_at > now()

    def public(self):
        return {"ip": self.ip, "expires_at": iso(self.expires_at), "created_at": iso(self.created_at)}


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"
    id = db.Column(db.Integer, primary_key=True)
    src_ip = db.Column(db.String(45), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now, index=True)
