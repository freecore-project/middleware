"""Add opt-in Bastille service configuration

Revision ID: d4b7e29c5a61
Revises: 7a2c91e4b6d0
Create Date: 2026-08-24 21:30:00.000000+00:00

"""
import sqlalchemy as sa
from alembic import op

revision = 'd4b7e29c5a61'
down_revision = '7a2c91e4b6d0'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'services_bastille',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('bastille_pool', sa.String(length=120), nullable=True),
        sa.Column(
            'bastille_startup_delay',
            sa.Integer(),
            nullable=False,
            server_default=sa.text('0'),
        ),
        sa.Column(
            'bastille_parallel_limit',
            sa.Integer(),
            nullable=False,
            server_default=sa.text('1'),
        ),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_services_bastille')),
    )
    op.execute(
        'INSERT INTO services_bastille '
        '(bastille_pool, bastille_startup_delay, bastille_parallel_limit) '
        'VALUES (NULL, 0, 1)'
    )
    op.execute(
        "INSERT INTO services_services (srv_service, srv_enable) VALUES ('bastille', 0)"
    )


def downgrade():
    op.execute("DELETE FROM services_services WHERE srv_service = 'bastille'")
    op.drop_table('services_bastille')
