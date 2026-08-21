# freecore/the internal development record: TrueCommand Cloud support is removed from FreeCORE.
# The plugins/truecommand/ package (portal.ixsystems.com registration, the
# WireGuard tunnel to iX's cloud, and its polling state machine) is deleted;
# this stub keeps the public API surface answering with the truth of a box
# that was never registered. Self-hosted TrueCommand needs nothing here --
# it is an external client of the websocket API.
import errno

import middlewared.sqlalchemy as sa
from middlewared.schema import accepts, Bool, Dict, Str
from middlewared.service import CallError, Service

STATUS = 'DISABLED'
STATUS_REASON = 'Truecommand service is disabled.'


class TrueCommandModel(sa.Model):
    # The table is alembic-managed and read DIRECTLY by the nginx etc template
    # (`datastore.config system.truecommand`), so the model must stay registered
    # even with the feature removed (the internal development record datastore-stub rule). The wireguard
    # wg0.conf template read it too until freecore/the internal development record removed it.
    __tablename__ = 'system_truecommand'

    id = sa.Column(sa.Integer(), primary_key=True)
    api_key = sa.Column(sa.EncryptedText(), default=None, nullable=True)
    api_key_state = sa.Column(sa.String(128), default='DISABLED', nullable=True)
    wg_public_key = sa.Column(sa.String(255), default=None, nullable=True)
    wg_private_key = sa.Column(sa.EncryptedText(), default=None, nullable=True)
    wg_address = sa.Column(sa.String(255), default=None, nullable=True)
    tc_public_key = sa.Column(sa.String(255), default=None, nullable=True)
    endpoint = sa.Column(sa.String(255), default=None, nullable=True)
    remote_address = sa.Column(sa.String(255), default=None, nullable=True)
    enabled = sa.Column(sa.Boolean(), default=False)


class TruecommandService(Service):

    @accepts()
    async def config(self):
        """
        TrueCommand Cloud configuration (removed feature; permanently disabled).
        """
        return {
            'id': 1,
            'api_key': None,
            'enabled': False,
            'remote_url': None,
            'remote_ip_address': None,
            'status': STATUS,
            'status_reason': STATUS_REASON,
        }

    @accepts(Dict(
        'truecommand_update',
        Bool('enabled'),
        Str('api_key', null=True),
    ))
    async def update(self, data):
        """
        TrueCommand Cloud support has been removed; enabling is refused.
        """
        if data.get('enabled'):
            raise CallError(
                'TrueCommand Cloud support has been removed from FreeCORE.',
                errno.EOPNOTSUPP,
            )
        return await self.config()

    @accepts()
    async def connected(self):
        """
        Always reports no TrueCommand Cloud connection (removed feature).
        """
        return {
            'connected': False,
            'truecommand_ip': None,
            'truecommand_url': None,
            'status': STATUS,
            'status_reason': STATUS_REASON,
        }


async def setup(middleware):
    # Fresh installs ship an empty system_truecommand table (the factory db has
    # no row; the deleted ConfigService used to auto-create it). The nginx
    # template hard-reads the row, so seed the never-registered default here.
    if not await middleware.call('datastore.query', 'system.truecommand'):
        await middleware.call('datastore.insert', 'system.truecommand', {
            'api_key': None,
            'api_key_state': 'DISABLED',
            'wg_public_key': None,
            'wg_private_key': None,
            'wg_address': None,
            'tc_public_key': None,
            'endpoint': None,
            'remote_address': None,
            'enabled': False,
        })
