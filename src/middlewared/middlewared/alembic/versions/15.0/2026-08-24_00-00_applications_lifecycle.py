"""Add native Applications lifecycle configuration

Revision ID: 7a2c91e4b6d0
Revises: a3f6c2b81e75
Create Date: 2026-08-24 20:30:00.000000+00:00

"""
import sqlalchemy as sa
from alembic import op

revision = '7a2c91e4b6d0'
down_revision = 'a3f6c2b81e75'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'services_applications',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('app_pool', sa.String(length=120), nullable=True),
        sa.Column('app_subnet', sa.String(length=43), nullable=False),
        sa.Column(
            'app_restart_on_boot',
            sa.Boolean(),
            nullable=False,
            server_default=sa.text('0'),
        ),
        sa.Column(
            'app_pf_owned',
            sa.Boolean(),
            nullable=False,
            server_default=sa.text('0'),
        ),
        sa.Column('app_filter_local_original', sa.Integer(), nullable=True),
        sa.Column('app_ipv4_forwarding_original', sa.Integer(), nullable=True),
        sa.Column('app_bridge_pfil_member_original', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_services_applications')),
    )
    op.execute(
        "INSERT INTO services_applications "
        "(app_pool, app_subnet, app_restart_on_boot, app_pf_owned, "
        "app_filter_local_original, app_ipv4_forwarding_original, "
        "app_bridge_pfil_member_original) "
        "VALUES (NULL, '10.88.0.0/16', 0, 0, NULL, NULL, NULL)"
    )


def downgrade():
    op.drop_table('services_applications')
