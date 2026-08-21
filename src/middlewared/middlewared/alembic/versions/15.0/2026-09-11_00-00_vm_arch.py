"""Give a VM a guest architecture

Revision ID: 4f2e8b7d1c60
Revises: c5e1a7b93d24
Create Date: 2026-09-11 00:00:00.000000+00:00

The QEMU lane (the internal development record) puts emulated aarch64 and riscv64 guests
beside bhyve's amd64 ones in the same vm.* namespace, told apart by one column.
Every VM that exists today is an amd64 bhyve VM, so the column is backfilled
with that and made NOT NULL: a row without an architecture is not a state the
plugin has to reason about.
"""
import sqlalchemy as sa
from alembic import op

revision = '4f2e8b7d1c60'
down_revision = 'c5e1a7b93d24'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('vm_vm', schema=None) as batch_op:
        batch_op.add_column(sa.Column('arch', sa.String(length=20), nullable=False, server_default='amd64'))


def downgrade():
    with op.batch_alter_table('vm_vm', schema=None) as batch_op:
        batch_op.drop_column('arch')
