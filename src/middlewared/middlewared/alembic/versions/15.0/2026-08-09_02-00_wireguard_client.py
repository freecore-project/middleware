"""Add the WireGuard client service

Revision ID: c93b6f0e7a15
Revises: 8e2d5c17ab94
Create Date: 2026-08-09 02:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = 'c93b6f0e7a15'
down_revision = '8e2d5c17ab94'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'services_wireguardclient',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('wgc_private_key', sa.TEXT(), nullable=True),
        sa.Column('wgc_public_key', sa.TEXT(), nullable=True),
        sa.Column('wgc_address', sa.String(length=45), nullable=True),
        sa.Column('wgc_netmask', sa.Integer(), nullable=False),
        sa.Column('wgc_peer_public_key', sa.TEXT(), nullable=True),
        sa.Column('wgc_preshared_key', sa.TEXT(), nullable=True),
        sa.Column('wgc_endpoint', sa.String(length=255), nullable=True),
        sa.Column('wgc_allowed_ips', sa.TEXT(), nullable=False),
        sa.Column('wgc_keepalive', sa.Integer(), nullable=True),
        sa.Column('wgc_mtu', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_services_wireguardclient')),
    )

    # Seeded empty; config_valid() refuses until there is a key, an address, a peer
    # key and an endpoint, which is what keeps the etc template from rendering a
    # half-formed wg2.conf that wg-quick would then fail on.
    op.execute(
        "INSERT INTO services_wireguardclient ("
        "wgc_private_key, wgc_public_key, wgc_address, wgc_netmask, wgc_peer_public_key, "
        "wgc_preshared_key, wgc_endpoint, wgc_allowed_ips, wgc_keepalive, wgc_mtu"
        ") VALUES ('', '', '', 32, '', NULL, '', '', NULL, NULL)"
    )

    # Fork rule 5: new features ship opt-in.
    op.execute("INSERT INTO services_services (srv_service, srv_enable) VALUES ('wireguard_client', 0)")


def downgrade():
    op.execute("DELETE FROM services_services WHERE srv_service = 'wireguard_client'")
    op.drop_table('services_wireguardclient')
