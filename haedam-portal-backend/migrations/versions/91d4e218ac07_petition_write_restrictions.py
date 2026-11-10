"""H1 per-account petition write restriction with retained ticket ownership."""
from alembic import op
import sqlalchemy as sa

revision = '91d4e218ac07'
down_revision = '7c2e9a41d5b3'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('petition_write_restrictions',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('ticket_id', sa.String(15), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('released_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_petition_write_restrictions_user_id_users')),
        sa.PrimaryKeyConstraint('user_id', 'ticket_id', name=op.f('pk_petition_write_restrictions')))


def downgrade():
    op.drop_table('petition_write_restrictions')
