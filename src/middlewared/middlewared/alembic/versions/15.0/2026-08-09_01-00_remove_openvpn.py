"""Remove the OpenVPN server and client services

Revision ID: 8e2d5c17ab94
Revises: 4b7c1f0a9d32
Create Date: 2026-08-09 01:00:00.000000+00:00

"""
from alembic import op


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
    # the internal development record: TrueNAS 13.3's own DDL for both tables, taken from its factory database,
    # so a configuration exported for TrueNAS SCALE carries 13.3's schema: NOT NULL columns, the certificate
    # foreign keys and their indexes (a plain create_table had left all three out).
    for statement in (
        """CREATE TABLE services_openvpnclient (
            id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol VARCHAR(4) NOT NULL,
            device_type VARCHAR(4) NOT NULL,
            nobind BOOLEAN NOT NULL,
            authentication_algorithm VARCHAR(32),
            tls_crypt_auth TEXT,
            cipher VARCHAR(32),
            compression VARCHAR(32),
            additional_parameters TEXT NOT NULL,
            client_certificate_id INTEGER,
            root_ca_id INTEGER,
            remote VARCHAR(120) NOT NULL,
            CONSTRAINT pk_services_openvpnclient PRIMARY KEY (id),
            CONSTRAINT fk_services_openvpnclient_client_certificate_id_system_certificate
                FOREIGN KEY(client_certificate_id)
                REFERENCES system_certificate (id),
            CONSTRAINT fk_services_openvpnclient_root_ca_id_system_certificateauthority FOREIGN KEY(root_ca_id)
                REFERENCES system_certificateauthority (id)
)""",
        """CREATE TABLE services_openvpnserver (
            id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol VARCHAR(4) NOT NULL,
            device_type VARCHAR(4) NOT NULL,
            authentication_algorithm VARCHAR(32),
            tls_crypt_auth TEXT,
            cipher VARCHAR(32),
            compression VARCHAR(32),
            additional_parameters TEXT NOT NULL,
            server_certificate_id INTEGER,
            root_ca_id INTEGER,
            server VARCHAR(45) NOT NULL,
            topology VARCHAR(16),
            netmask INTEGER NOT NULL,
            CONSTRAINT pk_services_openvpnserver PRIMARY KEY (id),
            CONSTRAINT fk_services_openvpnserver_root_ca_id_system_certificateauthority FOREIGN KEY(root_ca_id)
                REFERENCES system_certificateauthority (id),
            CONSTRAINT fk_services_openvpnserver_server_certificate_id_system_certificate
                FOREIGN KEY(server_certificate_id)
                REFERENCES system_certificate (id)
)""",
        """CREATE INDEX ix_services_openvpnclient_client_certificate_id
            ON services_openvpnclient (client_certificate_id)""",
        """CREATE INDEX ix_services_openvpnclient_root_ca_id ON services_openvpnclient (root_ca_id)""",
        """CREATE INDEX ix_services_openvpnserver_root_ca_id ON services_openvpnserver (root_ca_id)""",
        """CREATE INDEX ix_services_openvpnserver_server_certificate_id
            ON services_openvpnserver (server_certificate_id)""",
    ):
        op.execute(statement)
    op.execute("INSERT INTO services_services (srv_service, srv_enable) VALUES ('openvpn_client', 0)")
    op.execute("INSERT INTO services_services (srv_service, srv_enable) VALUES ('openvpn_server', 0)")
