import errno

from middlewared.schema import accepts, Bool, Dict, Int, Str
from middlewared.service import (
    job, no_auth_required, pass_app, private, throttle, CallError, Service,
)


def throttle_condition(middleware, app, *args, **kwargs):
    # app is None means internal middleware call
    if app is None or (app and app.authenticated):
        return True, 'AUTHENTICATED'
    return False, None


class FailoverService(Service):
    """
    Stand-in for the removed proprietary failover plugin (freecore/the internal development record).
    Method surface and return values match what the licensed plugin produced on a
    single-node system without an HA license, so callers behave identically.
    """

    @accepts(Dict(
        'failover_update',
        Bool('disabled'),
        Int('timeout'),
        Bool('master'),
    ))
    @job(lock='failover_update')
    async def update(self, job, data):
        """
        Failover is not supported on this system; accepted for API
        compatibility, nothing is persisted.
        """
        return data

    @accepts()
    def licensed(self):
        """
        Failover is never licensed on this system.
        """
        return False

    @no_auth_required
    @throttle(seconds=2, condition=throttle_condition)
    @accepts()
    @pass_app(rest=True)
    async def status(self, app):
        """
        Single-node system: always SINGLE.
        """
        return 'SINGLE'

    @accepts()
    async def node(self):
        """
        Slot position cannot be determined on non-HA hardware.
        """
        return 'MANUAL'

    @accepts()
    async def hardware(self):
        """
        No iX HA chassis is ever detected on this system.
        """
        return 'MANUAL'

    @private
    async def config(self):
        return {'id': 1, 'disabled': True, 'master': False, 'timeout': 0}

    @accepts()
    def in_progress(self):
        return False

    @private
    async def is_single_master_node(self):
        return True

    @no_auth_required
    @throttle(seconds=2, condition=throttle_condition)
    @accepts()
    @pass_app()
    def disabled_reasons(self, app):
        return ['NO_LICENSE']

    @private
    async def internal_interfaces(self):
        return []

    @private
    async def force_master(self):
        return False

    @accepts(
        Str('action', enum=['ENABLE', 'DISABLE']),
        Dict(
            'options',
            Bool('active'),
        ),
    )
    async def control(self, action, options=None):
        return None

    @private
    def upgrade_version(self):
        return 1

    @private
    async def call_remote(self, method, args=None, kwargs=None):
        raise CallError('Failover is not licensed', errno.ENOTSUP)

    @private
    async def remote_ip(self):
        raise CallError('Failover is not licensed', errno.ENOTSUP)

    @private
    async def send_database(self):
        return None

    @private
    async def send_small_file(self, path, dest=None):
        return None


class FailoverVipService(Service):

    class Config:
        namespace = 'failover.vip'

    @private
    async def get_states(self, interfaces=None):
        # (masters, backups, inits) — no CARP interfaces without failover
        return [[], [], []]
