"""Record a return point back to the 13.3 boot environment

Revision ID: a7f2c9d4e610
Revises: c93b6f0e7a15
Create Date: 2026-08-09 03:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = 'a7f2c9d4e610'
down_revision = 'c93b6f0e7a15'
branch_labels = None
depends_on = None


def upgrade():
    # Single row, and deliberately NOT seeded: an empty table means this system has no
    # captured return, and with no row the feature is completely inert.
    op.create_table(
        'system_rollbackwindow',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('origin_be', sa.String(length=255), nullable=False),
        sa.Column('arrival_path', sa.String(length=32), nullable=False),
        sa.Column('captured_at', sa.DateTime(), nullable=False),
        sa.Column('system_dataset', sa.String(length=255), nullable=False),
        sa.Column('snapshots', sa.TEXT(), nullable=False),
        sa.Column('pool_state', sa.TEXT(), nullable=False),
        sa.Column('closed_reason', sa.String(length=32), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_system_rollbackwindow')),
    )


def downgrade():
    op.drop_table('system_rollbackwindow')
