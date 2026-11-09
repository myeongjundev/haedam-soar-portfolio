"""add_blocked_ips

Revision ID: 7c2e9a41d5b3
Revises: 04440ce16125
Create Date: 2026-10-20 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7c2e9a41d5b3'
down_revision = '04440ce16125'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('blocked_ips',
    sa.Column('ip', sa.String(length=45), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('ip', name=op.f('pk_blocked_ips'))
    )


def downgrade():
    op.drop_table('blocked_ips')
