import ipaddress
import subprocess

from middlewared.schema import accepts, Bool, Dict, Int, IPAddr, List, Patch, Str
from middlewared.service import CallError, CRUDService, filterable, private, SystemServiceService, ValidationErrors
from middlewared.plugins.wireguard_.runtime import peer_status_rows, read_peer_runtime
import middlewared.sqlalchemy as sa
from middlewared.utils import filter_list
from middlewared.validators import Port, Range

# wg-quick(8) reads its interface configs from ${LOCALBASE}/etc/wireguard on FreeBSD.
# Interface allocation: wg1 belongs to the server, wg2 to the client -- so neither can
# ever fight over an interface or a config file.  wg0 used to be TrueCommand Cloud's
# outbound tunnel; that machinery went with freecore/the internal development record and nothing owns wg0
# now.  Do not reuse the name: it still appears in inherited docs and in 13.3 configs.
WG_INTERFACE = 'wg1'
WG_CLIENT_INTERFACE = 'wg2'

# A WireGuard key is 32 bytes, base64 encoded -- 44 characters ending in '='.
WG_KEY_LENGTH = 44


class WireguardModel(sa.Model):
    __tablename__ = 'services_wireguard'

    id = sa.Column(sa.Integer(), primary_key=True)
    wg_private_key = sa.Column(sa.EncryptedText(), nullable=True)
    wg_public_key = sa.Column(sa.Text(), nullable=True)
    wg_listen_port = sa.Column(sa.Integer(), default=51820)
    wg_address = sa.Column(sa.String(45), default='10.100.0.1')
    wg_netmask = sa.Column(sa.Integer(), default=24)
    wg_mtu = sa.Column(sa.Integer(), nullable=True)
    wg_dns = sa.Column(sa.String(255), nullable=True)
    wg_endpoint = sa.Column(sa.String(255), nullable=True)


class WireguardPeerModel(sa.Model):
    __tablename__ = 'services_wireguardpeer'

    id = sa.Column(sa.Integer(), primary_key=True)
    wgp_name = sa.Column(sa.String(120))
    wgp_public_key = sa.Column(sa.Text())
    wgp_preshared_key = sa.Column(sa.EncryptedText(), nullable=True)
    wgp_allowed_ips = sa.Column(sa.Text())
    wgp_keepalive = sa.Column(sa.Integer(), nullable=True)
    wgp_enabled = sa.Column(sa.Boolean(), default=True)


# `wg pubkey` reads the private key on stdin, and middlewared.utils.run() cannot feed
# stdin -- it forwards **kwargs to create_subprocess_exec (which takes stdin, not input)
# and calls communicate() with no argument. So these shell out with subprocess and are
# dispatched through run_in_thread. Module-level so the server and client services share
# one implementation rather than each carrying a copy.
def public_key_for_sync(private_key):
    proc = subprocess.run(['wg', 'pubkey'], input=private_key.encode(), capture_output=True)
    if proc.returncode:
        raise CallError(
            f'Provided private key is not a valid WireGuard key: {proc.stderr.decode().strip()}'
        )
    return proc.stdout.decode().strip()


def generate_keypair_sync():
    proc = subprocess.run(['wg', 'genkey'], capture_output=True)
    if proc.returncode:
        raise CallError(
            f'Failed to generate a WireGuard private key ({proc.returncode}): '
            f'{proc.stderr.decode().strip()}'
        )
    private_key = proc.stdout.decode().strip()

    return {'private_key': private_key, 'public_key': public_key_for_sync(private_key)}


def validate_key(value, schema, field, verrors, required=True):
    """
    wg(8) accepts a key only if it is 32 bytes of base64. Checking here means a bad
    paste fails in the UI instead of silently producing a wg1.conf that wg-quick
    refuses at start time, where the only symptom is "service failed to start".
    """
    if not value:
        if required:
            verrors.add(f'{schema}.{field}', 'This field is required.')
        return

    if len(value) != WG_KEY_LENGTH or not value.endswith('='):
        verrors.add(
            f'{schema}.{field}',
            'A WireGuard key must be 32 bytes encoded as base64 (44 characters ending in "=").'
        )


class WireguardService(SystemServiceService):

    class Config:
        # SystemServiceService derives the datastore from the service name --
        # 'wireguard' -> services.wireguard. Do not set `datastore` here; it is ignored.
        service = 'wireguard'
        datastore_prefix = 'wg_'
        service_verb = 'restart'

    @private
    async def config_valid(self):
        config = await self.config()
        if not config['private_key']:
            raise CallError('Generate or provide a WireGuard private key first.')
        if not config['address']:
            raise CallError('Configure a WireGuard server address first.')

    @private
    async def generate_keypair(self):
        return await self.middleware.run_in_thread(generate_keypair_sync)

    @private
    async def public_key_for(self, private_key):
        return await self.middleware.run_in_thread(public_key_for_sync, private_key)

    @accepts()
    async def generate_keys(self):
        """
        Generate a new WireGuard keypair for this server and store it.

        Existing peers keep working only if they were configured with the *new* public
        key, so treat this as a re-key of the whole server: every peer configuration
        has to be regenerated and redistributed afterwards.
        """
        keys = await self.generate_keypair()
        return await self.update({'private_key': keys['private_key']})

    @accepts(Dict(
        'wireguard_update',
        Str('private_key', private=True, null=True),
        Int('listen_port', validators=[Port()]),
        IPAddr('address'),
        Int('netmask', validators=[Range(min=0, max=128)]),
        Int('mtu', null=True, validators=[Range(min=576, max=9000)]),
        Str('dns', null=True),
        Str('endpoint', null=True),
        update=True,
    ))
    async def do_update(self, data):
        """
        Update the WireGuard server configuration.

        `private_key` is the server's own key. Leave it alone and use
        `wireguard.generate_keys` unless you are importing an existing server.

        `endpoint` is the publicly reachable host (or host:port) written into generated
        peer configurations. It is not used by the server itself -- it exists so the
        configs handed to clients are usable without hand editing.
        """
        old = await self.config()
        new = old.copy()
        new.update(data)

        verrors = ValidationErrors()

        if new['private_key'] != old['private_key']:
            validate_key(new['private_key'], 'wireguard_update', 'private_key', verrors, required=False)

        if new['address']:
            try:
                version = ipaddress.ip_address(new['address']).version
            except ValueError:
                verrors.add('wireguard_update.address', 'Not a valid IP address.')
            else:
                if version == 4 and new['netmask'] > 32:
                    verrors.add(
                        'wireguard_update.netmask',
                        'For an IPv4 server address the netmask must be between 0 and 32.'
                    )

        verrors.check()

        # Keep the stored public key in step with the private key rather than making
        # the operator paste both -- the public key is derived, never independent.
        if new['private_key']:
            if new['private_key'] != old['private_key']:
                new['public_key'] = await self.public_key_for(new['private_key'])
        else:
            new['public_key'] = ''

        await self._update_service(old, new)

        return await self.config()


class WireguardPeerService(CRUDService):

    class Config:
        namespace = 'wireguard.peer'
        datastore = 'services.wireguardpeer'
        datastore_prefix = 'wgp_'
        datastore_extend = 'wireguard.peer.peer_extend'

    @filterable
    async def status(self, filters, options):
        """
        List configured peers with read-only state from the running server interface.

        Handshake timestamps are Unix seconds, handshake_age is seconds, and transfer
        counters are bytes. RECENT means a handshake within three minutes, not a
        continuous reachability check. Missing interface/peer state uses null values;
        zero handshake is NEVER_CONNECTED. Private and preshared keys are excluded.
        """
        peers = await self.query()
        snapshot = await self.middleware.run_in_thread(read_peer_runtime, WG_INTERFACE) if peers else {}
        return filter_list(peer_status_rows(peers, snapshot), filters, options)

    @private
    async def common_validation(self, data, schema):
        verrors = ValidationErrors()

        validate_key(data['public_key'], schema, 'public_key', verrors)
        if data.get('preshared_key'):
            validate_key(data['preshared_key'], schema, 'preshared_key', verrors, required=False)

        if not data['allowed_ips']:
            verrors.add(
                f'{schema}.allowed_ips',
                'At least one allowed IP or network is required, e.g. 10.100.0.2/32.'
            )
        else:
            for entry in data['allowed_ips']:
                try:
                    ipaddress.ip_network(entry, strict=False)
                except ValueError:
                    verrors.add(f'{schema}.allowed_ips', f'{entry!r} is not a valid IP address or network.')

        verrors.check()

    @private
    async def peer_extend(self, peer):
        peer['allowed_ips'] = [v for v in (peer['allowed_ips'] or '').split(',') if v]
        return peer

    @private
    async def peer_compress(self, peer):
        peer['allowed_ips'] = ','.join(peer['allowed_ips'])
        return peer

    @accepts(Dict(
        'wireguard_peer_create',
        Str('name', required=True, empty=False),
        Str('public_key', required=True, empty=False),
        Str('preshared_key', private=True, null=True, default=None),
        List('allowed_ips', items=[Str('network')], required=True),
        Int('keepalive', null=True, default=None, validators=[Range(min=1, max=65535)]),
        Bool('enabled', default=True),
        register=True,
    ))
    async def do_create(self, data):
        """
        Add a WireGuard peer.

        `public_key` is the peer's own public key -- the peer generates its keypair and
        gives you the public half. FreeCORE never sees a client private key.

        `allowed_ips` is the list of addresses this peer is permitted to use inside the
        tunnel. For a single roaming client that is one /32, e.g. `10.100.0.2/32`.
        """
        await self.common_validation(data, 'wireguard_peer_create')

        data['id'] = await self.middleware.call(
            'datastore.insert',
            self._config.datastore,
            await self.peer_compress(data.copy()),
            {'prefix': self._config.datastore_prefix},
        )

        await self._service_change('wireguard', 'restart')

        return await self.get_instance(data['id'])

    @accepts(
        Int('id'),
        Patch('wireguard_peer_create', 'wireguard_peer_update', ('attr', {'update': True})),
    )
    async def do_update(self, id, data):
        """
        Update a WireGuard peer.
        """
        old = await self.get_instance(id)
        new = old.copy()
        new.update(data)

        await self.common_validation(new, 'wireguard_peer_update')

        await self.middleware.call(
            'datastore.update',
            self._config.datastore,
            id,
            await self.peer_compress(new.copy()),
            {'prefix': self._config.datastore_prefix},
        )

        await self._service_change('wireguard', 'restart')

        return await self.get_instance(id)

    @accepts(Int('id'))
    async def do_delete(self, id):
        """
        Delete a WireGuard peer.
        """
        response = await self.middleware.call('datastore.delete', self._config.datastore, id)

        await self._service_change('wireguard', 'restart')

        return response

    @accepts(Int('id'))
    async def peer_configuration_generation(self, id):
        """
        Return a ready-to-use WireGuard configuration for `id`.

        The peer's own private key is deliberately left as a placeholder: it is generated
        on the client and never transits or is stored by FreeCORE. Everything else --
        server public key, endpoint, allowed IPs, DNS -- is filled in.
        """
        await self.middleware.call('wireguard.config_valid')
        config = await self.middleware.call('wireguard.config')
        peer = await self.get_instance(id)

        if not config['endpoint']:
            raise CallError(
                'Set the WireGuard server endpoint (the publicly reachable host) before generating '
                'peer configurations.'
            )

        endpoint = config['endpoint']
        if ':' not in endpoint.rsplit(']', 1)[-1]:
            endpoint = f'{endpoint}:{config["listen_port"]}'

        lines = [
            '[Interface]',
            '# Replace this with the private key generated on the client (wg genkey).',
            'PrivateKey = <CLIENT PRIVATE KEY>',
            f'Address = {", ".join(peer["allowed_ips"])}',
        ]
        if config['dns']:
            lines.append(f'DNS = {config["dns"]}')
        if config['mtu']:
            lines.append(f'MTU = {config["mtu"]}')

        lines += [
            '',
            '[Peer]',
            f'PublicKey = {config["public_key"]}',
            f'Endpoint = {endpoint}',
            'AllowedIPs = 0.0.0.0/0, ::/0',
        ]
        if peer['preshared_key']:
            lines.append(f'PresharedKey = {peer["preshared_key"]}')
        if peer['keepalive']:
            lines.append(f'PersistentKeepalive = {peer["keepalive"]}')

        return '\n'.join(lines) + '\n'


class WireguardClientModel(sa.Model):
    __tablename__ = 'services_wireguardclient'

    id = sa.Column(sa.Integer(), primary_key=True)
    wgc_private_key = sa.Column(sa.EncryptedText(), nullable=True)
    wgc_public_key = sa.Column(sa.Text(), nullable=True)
    wgc_address = sa.Column(sa.String(45), nullable=True)
    wgc_netmask = sa.Column(sa.Integer(), default=32)
    wgc_peer_public_key = sa.Column(sa.Text(), nullable=True)
    wgc_preshared_key = sa.Column(sa.EncryptedText(), nullable=True)
    wgc_endpoint = sa.Column(sa.String(255), nullable=True)
    wgc_allowed_ips = sa.Column(sa.Text())
    wgc_keepalive = sa.Column(sa.Integer(), nullable=True)
    wgc_mtu = sa.Column(sa.Integer(), nullable=True)


class WireguardClientService(SystemServiceService):
    """
    Connect this system to a remote WireGuard server as a peer.

    This is the counterpart to the WireGuard server: the server accepts peers, this
    dials out. It replaces the OpenVPN client removed in the internal development record.
    """

    class Config:
        # namespace defaults to the lowercased class name minus "Service", which would
        # give 'wireguardclient'. Set explicitly so the API reads wireguard.client,
        # alongside wireguard.peer.
        namespace = 'wireguard.client'
        service = 'wireguard_client'
        # SystemServiceService resolves the datastore as services.<service_model or
        # service>; without service_model it would look for services.wireguard_client.
        service_model = 'wireguardclient'
        datastore_prefix = 'wgc_'
        service_verb = 'restart'
        datastore_extend = 'wireguard.client.client_extend'

    @private
    async def client_extend(self, data):
        data['allowed_ips'] = [v for v in (data['allowed_ips'] or '').split(',') if v]
        return data

    @private
    async def config_valid(self):
        config = await self.config()
        for field, message in (
            ('private_key', 'Generate or provide a WireGuard private key first.'),
            ('address', 'Configure the address this system uses inside the tunnel first.'),
            ('peer_public_key', 'Configure the remote server\'s public key first.'),
            ('endpoint', 'Configure the remote server endpoint first.'),
            ('allowed_ips', 'Configure at least one allowed IP or network first.'),
        ):
            if not config[field]:
                raise CallError(message)

    @private
    async def generate_keypair(self):
        return await self.middleware.run_in_thread(generate_keypair_sync)

    @accepts()
    async def generate_keys(self):
        """
        Generate a new WireGuard keypair for this client and store it.

        The remote server operator has to be given the new public key before the tunnel
        will come up again -- re-keying here does not tell them.
        """
        keys = await self.generate_keypair()
        return await self.update({'private_key': keys['private_key']})

    @accepts(Dict(
        'wireguard_client_update',
        Str('private_key', private=True, null=True),
        IPAddr('address'),
        Int('netmask', validators=[Range(min=0, max=128)]),
        Str('peer_public_key'),
        Str('preshared_key', private=True, null=True),
        Str('endpoint'),
        List('allowed_ips', items=[Str('network')]),
        Int('keepalive', null=True, validators=[Range(min=1, max=65535)]),
        Int('mtu', null=True, validators=[Range(min=576, max=9000)]),
        update=True,
    ))
    async def do_update(self, data):
        """
        Update the WireGuard client configuration.

        `address` is the address this system is assigned *inside* the tunnel -- the
        remote server's operator tells you what it is; it is not something you pick.

        `peer_public_key` is the remote server's public key, and `endpoint` its
        reachable host, optionally with a port (`vpn.example.com:51820`).

        `allowed_ips` selects what traffic goes through the tunnel. Naming a default
        route (`0.0.0.0/0` or `::/0`) sends *all* of this system's traffic through the
        remote server, which can cut off access to this box from your own network.
        """
        old = await self.config()
        new = old.copy()
        new.update(data)

        verrors = ValidationErrors()

        if new['private_key'] != old['private_key']:
            validate_key(new['private_key'], 'wireguard_client_update', 'private_key', verrors, required=False)

        if new['peer_public_key']:
            validate_key(new['peer_public_key'], 'wireguard_client_update', 'peer_public_key', verrors)

        if new['preshared_key']:
            validate_key(
                new['preshared_key'], 'wireguard_client_update', 'preshared_key', verrors, required=False
            )

        if new['address']:
            try:
                version = ipaddress.ip_address(new['address']).version
            except ValueError:
                verrors.add('wireguard_client_update.address', 'Not a valid IP address.')
            else:
                if version == 4 and new['netmask'] > 32:
                    verrors.add(
                        'wireguard_client_update.netmask',
                        'For an IPv4 address the netmask must be between 0 and 32.'
                    )

        for entry in new['allowed_ips']:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                verrors.add(
                    'wireguard_client_update.allowed_ips',
                    f'{entry!r} is not a valid IP address or network.'
                )

        if new['endpoint'] and ' ' in new['endpoint']:
            verrors.add('wireguard_client_update.endpoint', 'Endpoint must not contain spaces.')

        verrors.check()

        if new['private_key']:
            if new['private_key'] != old['private_key']:
                new['public_key'] = await self.middleware.run_in_thread(
                    public_key_for_sync, new['private_key']
                )
        else:
            new['public_key'] = ''

        new['allowed_ips'] = ','.join(new['allowed_ips'])

        await self._update_service(old, new)

        return await self.config()
