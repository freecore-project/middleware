"""Remove the OpenVPN server and client services

Revision ID: 8e2d5c17ab94
Revises: 4b7c1f0a9d32
Create Date: 2026-08-09 01:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = '8e2d5c17ab94'
down_revision = '4b7c1f0a9d32'
branch_labels = None
depends_on = None


def upgrade():
    # Safe to drop outright rather than stub: the only readers of these tables were
    # plugins/vpn.py and the two etc templates, all removed in the same change. The
    # remaining callers (the certificate revoked-alert source and the CA in-use guard
    # in crypto.py) went through the openvpn.* service methods, not the datastore, and
    # are deleted too -- so nothing is left to read a stubbed row.
    op.execute("DELETE FROM services_services WHERE srv_service IN ('openvpn_server', 'openvpn_client')")
    op.drop_table('services_openvpnserver')
    op.drop_table('services_openvpnclient')


def downgrade():
    op.create_table(
        'services_openvpnclient',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(length=4), nullable=True),
        sa.Column('device_type', sa.String(length=4), nullable=True),
        sa.Column('nobind', sa.Boolean(), nullable=True),
        sa.Column('authentication_algorithm', sa.String(length=32), nullable=True),
        sa.Column('tls_crypt_auth', sa.TEXT(), nullable=True),
        sa.Column('remote', sa.String(length=120), nullable=True),
        sa.Column('cipher', sa.String(length=32), nullable=True),
        sa.Column('compression', sa.String(length=32), nullable=True),
        sa.Column('additional_parameters', sa.TEXT(), nullable=True),
        sa.Column('client_certificate_id', sa.Integer(), nullable=True),
        sa.Column('root_ca_id', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_services_openvpnclient')),
    )
    op.create_table(
        'services_openvpnserver',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.String(length=4), nullable=True),
        sa.Column('device_type', sa.String(length=4), nullable=True),
        sa.Column('authentication_algorithm', sa.String(length=32), nullable=True),
        sa.Column('tls_crypt_auth', sa.TEXT(), nullable=True),
        sa.Column('cipher', sa.String(length=32), nullable=True),
        sa.Column('compression', sa.String(length=32), nullable=True),
        sa.Column('additional_parameters', sa.TEXT(), nullable=True),
        sa.Column('server_certificate_id', sa.Integer(), nullable=True),
        sa.Column('root_ca_id', sa.Integer(), nullable=True),
        sa.Column('server', sa.String(length=45), nullable=True),
        sa.Column('topology', sa.String(length=16), nullable=True),
        sa.Column('netmask', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_services_openvpnserver')),
    )
    op.execute("INSERT INTO services_services (srv_service, srv_enable) VALUES ('openvpn_client', 0)")
    op.execute("INSERT INTO services_services (srv_service, srv_enable) VALUES ('openvpn_server', 0)")
