"""Applications: the two experimental opt-in flags

Revision ID: b7e3d19a5c42
Revises: 4f2e8b7d1c60
Create Date: 2026-09-13 00:00:00.000000+00:00

the internal development record: the Convert & Import lane and the Linux image
compatibility tier (#444) are each behind a boolean on the Applications
configuration. Both default to off, so a box that never touches them renders
the same rc.conf and loads no extra kernel module after this migration.
"""
import sqlalchemy as sa
from alembic import op

revision = 'b7e3d19a5c42'
down_revision = '4f2e8b7d1c60'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('services_applications', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'app_linux_compat_enabled', sa.Boolean(), nullable=False, server_default=sa.text('0'),
        ))
        batch_op.add_column(sa.Column(
            'app_convert_enabled', sa.Boolean(), nullable=False, server_default=sa.text('0'),
        ))


def downgrade():
    with op.batch_alter_table('services_applications', schema=None) as batch_op:
        batch_op.drop_column('app_convert_enabled')
        batch_op.drop_column('app_linux_compat_enabled')
