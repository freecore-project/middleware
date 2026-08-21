"""Remove the retired rollback-expiry column

Revision ID: f8b2d7c4a901
Revises: 2e957d41f147
Create Date: 2026-08-16 18:30:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = 'f8b2d7c4a901'
down_revision = '2e957d41f147'
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    columns = {
        column['name']
        for column in inspector.get_columns('system_rollbackwindow')
    }
    if 'expires_at' in columns:
        with op.batch_alter_table(
            'system_rollbackwindow', schema=None,
        ) as batch_op:
            batch_op.drop_column('expires_at')


def downgrade():
    # A persistent captured return has no expiry field to restore.
    pass
