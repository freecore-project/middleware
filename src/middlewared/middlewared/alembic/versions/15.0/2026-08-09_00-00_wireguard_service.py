"""Add WireGuard server service

Revision ID: 4b7c1f0a9d32
Revises: 6950c136c5ac
Create Date: 2026-08-09 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = '4b7c1f0a9d32'
down_revision = '6950c136c5ac'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'services_wireguard',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('wg_private_key', sa.TEXT(), nullable=True),
        sa.Column('wg_public_key', sa.TEXT(), nullable=True),
        sa.Column('wg_listen_port', sa.Integer(), nullable=False),
        sa.Column('wg_address', sa.String(length=45), nullable=False),
        sa.Column('wg_netmask', sa.Integer(), nullable=False),
        sa.Column('wg_mtu', sa.Integer(), nullable=True),
        sa.Column('wg_dns', sa.String(length=255), nullable=True),
        sa.Column('wg_endpoint', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_services_wireguard')),
    )

    op.create_table(
        'services_wireguardpeer',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('wgp_name', sa.String(length=120), nullable=False),
        sa.Column('wgp_public_key', sa.TEXT(), nullable=False),
        sa.Column('wgp_preshared_key', sa.TEXT(), nullable=True),
        sa.Column('wgp_allowed_ips', sa.TEXT(), nullable=False),
        sa.Column('wgp_keepalive', sa.Integer(), nullable=True),
        sa.Column('wgp_enabled', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_services_wireguardpeer')),
    )

    # Seed the singleton config row. Keys stay empty until the operator generates
    # them -- an empty private key is what config_valid() refuses on, which is what
    # keeps the etc template from rendering a half-formed wg1.conf.
    op.execute(
        "INSERT INTO services_wireguard ("
        "wg_private_key, wg_public_key, wg_listen_port, wg_address, wg_netmask, "
        "wg_mtu, wg_dns, wg_endpoint"
        ") VALUES ('', '', 51820, '10.100.0.1', 24, NULL, NULL, NULL)"
    )

    # Fork rule 5: new features ship opt-in.
    op.execute("INSERT INTO services_services (srv_service, srv_enable) VALUES ('wireguard', 0)")


def downgrade():
    op.execute("DELETE FROM services_services WHERE srv_service = 'wireguard'")
    op.drop_table('services_wireguardpeer')
    op.drop_table('services_wireguard')
