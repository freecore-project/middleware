"""WebAuthn security-key second factor

Revision ID: e8b3a5c1f972
Revises: c5e7d2a9b041
Create Date: 2026-08-02 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = 'e8b3a5c1f972'
down_revision = 'c5e7d2a9b041'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'system_webauthn',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_system_webauthn')),
    )
    op.execute('INSERT INTO system_webauthn (enabled) VALUES (0)')

    op.create_table(
        'system_webauthncredential',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('credential_id', sa.Text(), nullable=False),
        sa.Column('public_key', sa.Text(), nullable=False),
        sa.Column('sign_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('rp_id', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_used', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_system_webauthncredential')),
        sa.UniqueConstraint('credential_id', name=op.f('uq_system_webauthncredential_credential_id')),
    )


def downgrade():
    op.drop_table('system_webauthncredential')
    op.drop_table('system_webauthn')
