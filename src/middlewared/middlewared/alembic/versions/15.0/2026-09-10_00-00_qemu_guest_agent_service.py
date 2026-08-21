"""Register QEMU Guest Agent as a managed service

Revision ID: c5e1a7b93d24
Revises: d4b7e29c5a61
Create Date: 2026-09-10 00:00:00.000000+00:00

the internal development record shipped the agent with no service of its own, so the only way to
run it at boot was an RC tunable setting qemu_guest_agent_enable.  rc.conf renders
tunables *after* service-generated settings, so once the service owns that variable a
surviving enabled tunable would silently win over the boot checkbox and the two would
disagree.  The variable therefore moves to the service, and its meaning moves with it:
an enabled tunable that was turning the agent on leaves the service enabled, and
anything else leaves it disabled -- which is what those systems were already doing.

Every qemu_guest_agent_enable RC tunable is then removed, including a disabled one.
A disabled tunable never reached rc.conf, so dropping it changes no behaviour today;
leaving it would only preserve a second, contradictory owner of one variable.

qemu_guest_agent_flags and every other tunable are untouched: flags stay the
operator's, and only the enable variable changes hands.
"""
import sqlalchemy as sa
from alembic import op

revision = 'c5e1a7b93d24'
down_revision = 'd4b7e29c5a61'
branch_labels = None
depends_on = None

TRUE_VALUES = ('yes', 'true', 'on', '1')


def enable_from_tunables(rows):
    """Decide the service's boot setting from the RC tunables it replaces.

    ``rows`` are ``(id, value, enabled)``. Only an enabled tunable ever reached
    rc.conf, so only an enabled one is evidence that a system was starting the agent
    at boot; a disabled tunable, an explicit NO and no tunable at all are the same
    statement and all leave the service disabled.
    """
    for _id, value, enabled in rows:
        if enabled and str(value or '').strip().strip('"\'').lower() in TRUE_VALUES:
            return 1
    return 0


def upgrade():
    connection = op.get_bind()
    rows = connection.execute(sa.text(
        "SELECT id, tun_value, tun_enabled FROM system_tunable "
        "WHERE tun_type = 'RC' AND tun_var = 'qemu_guest_agent_enable'"
    )).fetchall()

    enable = enable_from_tunables(rows)

    connection.execute(
        sa.text(
            'INSERT INTO services_services (srv_service, srv_enable) '
            "VALUES ('qemu_guest_agent', :enable)"
        ),
        {'enable': enable},
    )

    for row in rows:
        connection.execute(
            sa.text('DELETE FROM system_tunable WHERE id = :id'), {'id': row[0]}
        )


def downgrade():
    # The tunables are not recreated: their meaning was carried into the service
    # row, and inventing one back would restore a second owner of the variable.
    op.execute("DELETE FROM services_services WHERE srv_service = 'qemu_guest_agent'")
