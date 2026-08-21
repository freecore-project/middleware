"""Redesigned web terminal toggle

Revision ID: 2e957d41f147
Revises: d4a1e8b70c53
Create Date: 2026-08-10 01:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = '2e957d41f147'
down_revision = 'd4a1e8b70c53'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'system_webterminal',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_system_webterminal')),
    )
    op.execute('INSERT INTO system_webterminal (enabled) VALUES (0)')


def downgrade():
    op.drop_table('system_webterminal')
