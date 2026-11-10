"""S4 lab account lock ownership; no existing account changes."""
from alembic import op
import sqlalchemy as sa

revision = "a640c2d1e910"
down_revision = "91d4e218ac07"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("s4_account_claims", sa.Column("user_id", sa.Integer(), nullable=False),
                    sa.Column("ticket_id", sa.String(20), nullable=False),
                    sa.ForeignKeyConstraint(["user_id"], ["users.id"]), sa.PrimaryKeyConstraint("user_id"))


def downgrade():
    op.drop_table("s4_account_claims")
