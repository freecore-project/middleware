"""Restore the OpenVPN server and client services

Revision ID: a3f6c2b81e75
Revises: f8b2d7c4a901
Create Date: 2026-09-08 00:00:00.000000+00:00

Re-creates what 8e2d5c17ab94 dropped.  Deliberately NOT a copy of that
revision's downgrade(): it rebuilt both tables without the foreign keys, without
the two certificate indexes and with every column nullable, which would have
left an upgraded box on a different schema than a fresh install.  The DDL below
is taken from the original creation migration (115caec86b91) so the two match.

"""
from alembic import op
import sqlalchemy as sa


revision = 'a3f6c2b81e75'
down_revision = 'f8b2d7c4a901'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'services_openvpnclient',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(length=4), nullable=False),
        sa.Column('device_type', sa.String(length=4), nullable=False),
        sa.Column('nobind', sa.Boolean(), nullable=False),
        sa.Column('authentication_algorithm', sa.String(length=32), nullable=True),
        sa.Column('tls_crypt_auth', sa.Text(), nullable=True),
        sa.Column('cipher', sa.String(length=32), nullable=True),
        sa.Column('compression', sa.String(length=32), nullable=True),
        sa.Column('additional_parameters', sa.Text(), nullable=False),
        sa.Column('client_certificate_id', sa.Integer(), nullable=True),
        sa.Column('root_ca_id', sa.Integer(), nullable=True),
        sa.Column('remote', sa.String(length=120), nullable=False),
        sa.ForeignKeyConstraint(
            ['client_certificate_id'], ['system_certificate.id'],
            name=op.f('fk_services_openvpnclient_client_certificate_id_system_certificate')
        ),
        sa.ForeignKeyConstraint(
            ['root_ca_id'], ['system_certificateauthority.id'],
            name=op.f('fk_services_openvpnclient_root_ca_id_system_certificateauthority')
        ),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_services_openvpnclient'))
    )
    with op.batch_alter_table('services_openvpnclient', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_services_openvpnclient_client_certificate_id'),
            ['client_certificate_id'], unique=False
        )
        batch_op.create_index(
            batch_op.f('ix_services_openvpnclient_root_ca_id'), ['root_ca_id'], unique=False
        )

    op.create_table(
        'services_openvpnserver',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(length=4), nullable=False),
        sa.Column('device_type', sa.String(length=4), nullable=False),
        sa.Column('authentication_algorithm', sa.String(length=32), nullable=True),
        sa.Column('tls_crypt_auth', sa.Text(), nullable=True),
        sa.Column('cipher', sa.String(length=32), nullable=True),
        sa.Column('compression', sa.String(length=32), nullable=True),
        sa.Column('additional_parameters', sa.Text(), nullable=False),
        sa.Column('server_certificate_id', sa.Integer(), nullable=True),
        sa.Column('root_ca_id', sa.Integer(), nullable=True),
        sa.Column('server', sa.String(length=45), nullable=False),
        sa.Column('topology', sa.String(length=16), nullable=True),
        sa.Column('netmask', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ['root_ca_id'], ['system_certificateauthority.id'],
            name=op.f('fk_services_openvpnserver_root_ca_id_system_certificateauthority')
        ),
        sa.ForeignKeyConstraint(
            ['server_certificate_id'], ['system_certificate.id'],
            name=op.f('fk_services_openvpnserver_server_certificate_id_system_certificate')
        ),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_services_openvpnserver'))
    )
    with op.batch_alter_table('services_openvpnserver', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_services_openvpnserver_root_ca_id'), ['root_ca_id'], unique=False
        )
        batch_op.create_index(
            batch_op.f('ix_services_openvpnserver_server_certificate_id'),
            ['server_certificate_id'], unique=False
        )

    op.execute("INSERT INTO services_services (srv_service, srv_enable) VALUES ('openvpn_client', 0)")
    op.execute("INSERT INTO services_services (srv_service, srv_enable) VALUES ('openvpn_server', 0)")


def downgrade():
    op.execute("DELETE FROM services_services WHERE srv_service IN ('openvpn_server', 'openvpn_client')")
    with op.batch_alter_table('services_openvpnserver', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_services_openvpnserver_server_certificate_id'))
        batch_op.drop_index(batch_op.f('ix_services_openvpnserver_root_ca_id'))

    op.drop_table('services_openvpnserver')
    with op.batch_alter_table('services_openvpnclient', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_services_openvpnclient_root_ca_id'))
        batch_op.drop_index(batch_op.f('ix_services_openvpnclient_client_certificate_id'))

    op.drop_table('services_openvpnclient')
