import asyncio
import contextlib
import ipaddress
import os
import re
import shlex
import stat
from pathlib import Path

import middlewared.sqlalchemy as sa
from middlewared.common.attachment import FSAttachmentDelegate
from middlewared.plugins.bastille_.utils import (
    BASTILLE_BASE_CONFIG,
    BASTILLE_DEFAULT_CONFIG,
    BASTILLE_PATH,
    BASTILLE_RC_PATH,
    BASTILLE_SAMPLE_CONFIG,
    MANAGED_PROPERTY,
    POOL_NAME,
    apply_config_pointer,
    atomic_write,
    bastille_dataset_specs,
    bastille_paths,
    render_bastille_config,
    strip_config_pointer,
)
from middlewared.plugins.service_.services.base_freebsd import freebsd_service
from middlewared.schema import Dict, Int, Str, accepts
from middlewared.service import Service, filterable, job, lock, private
from middlewared.service_exception import CallError, ValidationErrors
from middlewared.utils import filter_list, run
from middlewared.utils.path import is_child
from middlewared.validators import Match, Range

JAIL_NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
FREEBSD_RELEASE = re.compile(
    r'^(?:1[3-5])\.[0-9]-(?:RELEASE|STABLE|CURRENT|RC[1-9]|BETA[1-9])$'
)
JAIL_CONFIG_ADDRESS = re.compile(
    r'^\s*(?P<family>ip[46])\.addr\s*(?:\+?=)\s*(?P<value>.+?)\s*;\s*(?:#.*)?$',
    re.MULTILINE,
)
RC_CONFIG_INTERFACE = re.compile(
    r'^\s*ifconfig_[A-Za-z0-9_.:-]+\s*=\s*(["\'])(?P<value>.*?)\1\s*$',
    re.MULTILINE,
)
JAIL_CONFIG_DIRECTIVE = re.compile(
    r'^\s*(?P<name>[A-Za-z][A-Za-z0-9_.]*)'
    r'(?:\s*(?P<operator>\+?=)\s*(?P<value>.*?))?\s*;\s*(?:#.*)?$'
)
# the internal development record: a VNET jail owns its addresses, so while it runs they are read
# from inside it the way `bastille list` does. `vnet;` is how bastille marks one.
VNET_DIRECTIVE = re.compile(r'^\s*vnet\s*;\s*(?:#.*)?$', re.MULTILINE)
IFCONFIG_INTERFACE_LINE = re.compile(r'^(?P<name>[A-Za-z0-9_.:-]+):\s+flags=')
IFCONFIG_ADDRESS_LINE = re.compile(r'^\s+(?P<family>inet6?)\s+(?P<value>\S+)(?P<rest>.*)$')
BASTILLE_LIVE_ADDRESS_TIMEOUT = 10
SYSRC_SETTING = re.compile(
    r'^\s*(?P<name>[A-Za-z][A-Za-z0-9_]*)\s*=\s*(?P<value>.*?)\s*$', re.MULTILINE
)
MAX_JAIL_CONFIG_SIZE = 1024 * 1024
MAX_COMMAND_ERROR_SIZE = 4096
MAX_CONSOLE_LOG_BYTES = 256 * 1024
BASTILLE_CAPABILITY_PATH = '/usr/local/share/bastille/freecore-lifecycle-v3'
BASTILLE_CAPABILITY = (
    'freecore-bastille-lifecycle-v3\n'
    'upstream=1.4.0.260219\n'
    'portrevision=5\n'
)
RC_CONFIG_PATH = '/etc/rc.conf.freenas'
RESERVED_BASTILLE_TARGETS = {'all', 'boot', 'depend', 'help', 'off', 'on', 'priority'}


class BastilleModel(sa.Model):
    __tablename__ = 'services_bastille'

    id = sa.Column(sa.Integer(), primary_key=True)
    bastille_pool = sa.Column(sa.String(120), nullable=True)
    bastille_startup_delay = sa.Column(sa.Integer(), default=0)
    bastille_parallel_limit = sa.Column(sa.Integer(), default=1)


class BastilleService(Service):

    class Config:
        namespace = 'bastille'

    def _unavailable_pool_names(self):
        pools = getattr(self, '_pool_unavailable_in_progress', None)
        if pools is None:
            pools = self._pool_unavailable_in_progress = set()
        return pools

    def _pool_is_unavailable(self, pool_name):
        return bool(pool_name and pool_name in self._unavailable_pool_names())

    def _pool_stop_runtime_names(self):
        running = getattr(self, '_pool_stop_runtime', None)
        if running is None:
            running = self._pool_stop_runtime = {}
        return running

    async def _raw_config(self):
        return await self.middleware.call(
            'datastore.config', 'services.bastille', {'prefix': 'bastille_'}
        )

    async def _service_row(self):
        rows = await self.middleware.call(
            'datastore.query', 'services.services', [('srv_service', '=', 'bastille')]
        )
        return rows[0] if rows else None

    async def _active_controller(self):
        return await self.middleware.call('failover.status') in {'MASTER', 'SINGLE'}

    async def _validate_pool(self, pool_name, require_unused):
        verrors = ValidationErrors()
        if not isinstance(pool_name, str) or not POOL_NAME.fullmatch(pool_name):
            verrors.add('bastille_configure.pool', 'Bastille pool name is invalid.')
            verrors.check()

        if not await self._active_controller():
            verrors.add(
                'bastille_configure.pool',
                'Bastille can only be configured on the active controller.',
            )

        pools = await self.middleware.call('pool.query', [('name', '=', pool_name)])
        if not pools:
            verrors.add('bastille_configure.pool', f'Pool {pool_name!r} is not imported.')
        else:
            pool = pools[0]
            if pool_name == await self.middleware.call('boot.pool_name'):
                verrors.add('bastille_configure.pool', 'Bastille cannot use the boot pool.')
            if (
                pool.get('status') != 'ONLINE' or
                not pool.get('healthy', False) or
                not pool.get('is_decrypted', False)
            ):
                verrors.add(
                    'bastille_configure.pool',
                    'Bastille requires a healthy, online, unlocked data pool.',
                )

        if require_unused:
            dataset = bastille_paths(pool_name)['dataset']
            if await self.middleware.call('zfs.dataset.query', [('id', '=', dataset)]):
                verrors.add(
                    'bastille_configure.pool',
                    f'{dataset!r} already exists and is not owned by this configuration.',
                )

        if not os.access(BASTILLE_PATH, os.X_OK):
            verrors.add(
                'bastille_configure.pool',
                f'Bastille is not installed at {BASTILLE_PATH}.',
            )
        if not os.access(BASTILLE_RC_PATH, os.X_OK):
            verrors.add(
                'bastille_configure.pool',
                f'The packaged Bastille rc service is not installed at {BASTILLE_RC_PATH}.',
            )

        verrors.check()

    async def _managed_dataset_owners(self, pool_name):
        root = bastille_paths(pool_name)['dataset']
        result = await run(
            '/sbin/zfs', 'get', '-H', '-t', 'filesystem', '-o', 'name,value,source', '-r',
            MANAGED_PROPERTY, root, check=False, encoding='utf8',
        )
        if result.returncode:
            raise CallError(
                f'Unable to inspect the Bastille dataset hierarchy: {result.stderr.strip()}'
            )

        owners = {}
        for line in result.stdout.splitlines():
            fields = line.split('\t')
            if len(fields) == 3:
                owners[fields[0]] = (fields[1], fields[2])
        return owners

    async def _validate_managed_tree(self, pool_name):
        owners = await self._managed_dataset_owners(pool_name)
        for dataset, expected_owner in bastille_dataset_specs(pool_name):
            owner = owners.get(dataset)
            if owner != (expected_owner, 'local'):
                raise CallError(
                    f'Bastille dataset {dataset!r} is missing or does not have local '
                    f'{MANAGED_PROPERTY}={expected_owner!r} ownership.'
                )

    async def _validate_mounted_tree(self, pool_name):
        root = bastille_paths(pool_name)['dataset']
        result = await run(
            '/sbin/zfs', 'get', '-H', '-o', 'name,property,value', '-r',
            'mounted,mountpoint', root, check=False, encoding='utf8',
        )
        if result.returncode:
            raise CallError(
                f'Unable to inspect the Bastille dataset mounts: {result.stderr.strip()}'
            )

        properties = {}
        for line in result.stdout.splitlines():
            fields = line.split('\t')
            if len(fields) == 3:
                properties.setdefault(fields[0], {})[fields[1]] = fields[2]

        for dataset, _ in bastille_dataset_specs(pool_name):
            expected_logical = f'/{dataset}'
            expected_live = f'/mnt/{dataset}'
            dataset_properties = properties.get(dataset, {})
            if (
                dataset_properties.get('mounted') != 'yes' or
                dataset_properties.get('mountpoint') not in {expected_logical, expected_live} or
                not os.path.ismount(expected_live)
            ):
                raise CallError(
                    f'Bastille dataset {dataset!r} is not mounted at {expected_live!r}.'
                )

    @staticmethod
    def _configuration_file_valid(pool_name):
        path = bastille_paths(pool_name)['config_file']
        try:
            metadata = os.lstat(path)
            content = Path(path).read_text()
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            return False
        return (
            stat.S_ISREG(metadata.st_mode) and
            metadata.st_mode & 0o022 == 0 and
            content == render_bastille_config(pool_name)
        )

    async def _validate_configured_row(self, config):
        if not config.get('pool'):
            raise CallError('Select and configure a Bastille data pool first.')
        await self._validate_pool(config['pool'], False)
        await self._validate_managed_tree(config['pool'])
        await self._validate_mounted_tree(config['pool'])
        if not self._configuration_file_valid(config['pool']):
            raise CallError(
                'The generated Bastille configuration is missing, unsafe, or has been modified.'
            )
        return True

    async def _configuration_status(self, config):
        if not config.get('pool'):
            return False, None
        try:
            await self._validate_configured_row(config)
        except Exception as error:  # noqa: BLE001 -- report and fail closed on every inspection error
            return False, str(error)
        return True, None

    async def _lifecycle_config(self):
        config = await self._raw_config()
        if (
            getattr(self, '_pool_switch_in_progress', False) or
            self._pool_is_unavailable(config.get('pool'))
        ):
            raise CallError('Bastille storage configuration is changing or recovering.')
        await self._validate_configured_row(config)
        self._validate_package_capability()
        if os.path.lexists(bastille_paths(config['pool'])['pf_config']):
            raise CallError(
                'Middleware-managed Bastille jail lifecycle requires its PF configuration '
                'path to remain absent.'
            )
        return config

    @staticmethod
    def _package_capability_valid():
        try:
            metadata = os.lstat(BASTILLE_CAPABILITY_PATH)
            content = Path(BASTILLE_CAPABILITY_PATH).read_text(encoding='utf8')
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            return False
        return (
            stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o022 == 0 and
            content == BASTILLE_CAPABILITY
        )

    @classmethod
    def _validate_package_capability(cls):
        if not cls._package_capability_valid():
            raise CallError(
                'The installed Bastille package does not provide the required '
                'FreeCORE lifecycle capability.'
            )

    @staticmethod
    def _release_dataset_specs(pool_name, release):
        paths = bastille_paths(pool_name)
        return [
            (f'{paths["cache_dataset"]}/{release}', f'bastille:cache:{release}'),
            (f'{paths["releases_dataset"]}/{release}', f'bastille:release:{release}'),
        ]

    @staticmethod
    def _console_log_path(paths, jail_name):
        return os.path.join(paths['logs'], f'{jail_name}_console.log')

    @classmethod
    def _validate_console_log(cls, paths, jail_name, required=True):
        log_path = cls._console_log_path(paths, jail_name)
        try:
            metadata = os.lstat(log_path)
        except FileNotFoundError:
            if not required:
                return log_path
            raise CallError(f'Bastille jail console log {log_path!r} is missing.')
        except OSError as error:
            raise CallError(f'Unable to inspect Bastille jail console log {log_path!r}: {error}')
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise CallError(f'Bastille jail console log {log_path!r} is unsafe.')
        return log_path

    @staticmethod
    def _setting_value(content, name):
        values = []
        for match in SYSRC_SETTING.finditer(content):
            if match.group('name') != name:
                continue
            raw_value = match.group('value')
            try:
                tokens = shlex.split(raw_value)
            except ValueError as error:
                raise CallError(f'Unable to interpret Bastille {name!r} setting: {error}')
            if len(tokens) > 1:
                raise CallError(f'Bastille {name!r} setting is malformed.')
            values.append(tokens[0] if tokens else '')
        if len(values) > 1:
            raise CallError(f'Bastille {name!r} setting is duplicated.')
        return values[0] if values else None

    async def _validate_jail_identity(self, config, jail_name):
        """Prove a jail is safely ours to *operate*, not that it is ours to rewrite.

        Tier 1 of the two-tier contract (the internal development record). It asserts identity and
        containment only: a safe name, a real directory in this pool's Bastille jails
        store, a readable jail.conf, and a jail root inside that directory. It says
        nothing about our VNET metadata, our settings template, our fstab shape or the
        auxiliary conf files a CLI user is entitled to create, because none of those
        are needed to start, stop, attach to or read the log of a running prison.

        Every operation that *writes* to a jail keeps using _validate_owned_jail.
        """
        if (
            not JAIL_NAME.fullmatch(jail_name) or
            jail_name.lower() in RESERVED_BASTILLE_TARGETS
        ):
            raise CallError('Bastille jail name is invalid.')
        paths = bastille_paths(config['pool'])
        jails_root = os.path.realpath(paths['jails'])
        jail_path = os.path.join(paths['jails'], jail_name)
        try:
            directory_metadata = os.lstat(jail_path)
        except FileNotFoundError:
            raise CallError(f'Bastille jail {jail_name!r} does not exist.')
        except OSError as error:
            raise CallError(f'Unable to inspect Bastille jail {jail_name!r}: {error}')
        if (
            not stat.S_ISDIR(directory_metadata.st_mode) or
            stat.S_ISLNK(directory_metadata.st_mode)
        ):
            raise CallError(f'Bastille jail path {jail_path!r} is not a directory.')

        jail_config = self._read_bounded_regular_file(os.path.join(jail_path, 'jail.conf'))
        jail_root = os.path.join(jail_path, 'root')
        try:
            root_metadata = os.lstat(jail_root)
            contained = os.path.commonpath(
                [jails_root, os.path.realpath(jail_root)]
            ) == jails_root
        except (FileNotFoundError, OSError, ValueError) as error:
            raise CallError(f'Unable to inspect Bastille jail root {jail_root!r}: {error}')
        if (
            not contained or not stat.S_ISDIR(root_metadata.st_mode) or
            stat.S_ISLNK(root_metadata.st_mode)
        ):
            raise CallError(f'Bastille jail root {jail_root!r} is unsafe.')

        # jail.conf is read leniently -- a CLI user may legitimately carry directives we
        # never write -- but the one directive that decides which filesystem a prison is
        # given must still name this jail's own root.
        configured_paths = set()
        for line in jail_config.splitlines():
            match = JAIL_CONFIG_DIRECTIVE.fullmatch(line.strip())
            if match is None or match.group('name') != 'path' or match.group('operator') != '=':
                continue
            try:
                tokens = shlex.split(match.group('value'))
            except ValueError as error:
                raise CallError(
                    f'Unable to interpret Bastille jail {jail_name!r} configuration: {error}'
                )
            if len(tokens) != 1:
                raise CallError(f'Bastille jail {jail_name!r} has a malformed root directive.')
            configured_paths.add(os.path.normpath(tokens[0]))
        if configured_paths != {jail_root}:
            raise CallError(
                f'Bastille jail {jail_name!r} is not configured with a root inside its own storage.'
            )
        return {'name': jail_name, 'path': jail_path, 'root': jail_root}

    async def _running_jails(self, config, strict=False):
        if not config.get('pool'):
            return []

        result = await run(
            '/usr/sbin/jls', '-nq', 'name', 'path', check=False, encoding='utf8'
        )
        if result.returncode:
            raise CallError(f'Unable to inspect running jails: {result.stderr.strip()}')

        paths = bastille_paths(config['pool'])
        running = []
        for line in result.stdout.splitlines():
            try:
                values = dict(field.split('=', 1) for field in shlex.split(line))
            except (ValueError, TypeError) as error:
                if strict:
                    raise CallError(f'Unable to classify running jail state safely: {error}')
                continue
            name = values.get('name')
            jail_path = values.get('path')
            if not jail_path:
                if strict:
                    raise CallError('Unable to classify running jail state safely: path is missing.')
                continue
            normalized_path = os.path.normpath(jail_path)
            if strict:
                jails_path = os.path.normpath(paths['jails'])
                try:
                    inside_jails = os.path.commonpath(
                        [jails_path, normalized_path]
                    ) == jails_path
                except ValueError as error:
                    raise CallError(
                        f'Unable to classify running jail state safely: {error}'
                    )
                if not inside_jails:
                    continue

                relative_path = os.path.relpath(normalized_path, jails_path)
                parts = relative_path.split(os.sep)
                if (
                    len(parts) != 2 or parts[1] != 'root' or
                    not JAIL_NAME.fullmatch(parts[0]) or
                    parts[0].lower() in RESERVED_BASTILLE_TARGETS
                ):
                    raise CallError(
                        'Unable to classify running jail state safely: a jail path inside '
                        'the Bastille tree is not an exact managed jail root.'
                    )
                if not name or not JAIL_NAME.fullmatch(name) or name != parts[0]:
                    raise CallError(
                        'Unable to classify running jail state safely: '
                        'the reported jail name does not match its Bastille path.'
                    )
                running.append(parts[0])
                continue

            if not name or not JAIL_NAME.fullmatch(name):
                continue
            expected = os.path.join(paths['jails'], name, 'root')
            if normalized_path == expected and os.path.isfile(
                os.path.join(paths['jails'], name, 'jail.conf')
            ):
                running.append(name)
        return sorted(set(running))

    async def _running_jail_ids(self, config):
        """Map running Bastille jail names to jids; an unreadable inventory yields {}.

        the internal development record: the read-only page joins a query row to its guest.stats
        entry by jid. A jail that cannot be classified simply has no jid; it never fails
        the query. Classification mirrors _running_jails' lenient path.
        """
        if not config.get('pool'):
            return {}
        try:
            result = await run(
                '/usr/sbin/jls', '-nq', 'jid', 'name', 'path', check=False, encoding='utf8'
            )
        except OSError:
            return {}
        if result.returncode:
            return {}
        paths = bastille_paths(config['pool'])
        ids = {}
        for line in result.stdout.splitlines():
            try:
                values = dict(field.split('=', 1) for field in shlex.split(line))
                jid = int(values.get('jid', ''))
            except (ValueError, TypeError):
                continue
            name = values.get('name')
            jail_path = values.get('path')
            if jid < 1 or not name or not jail_path or not JAIL_NAME.fullmatch(name):
                continue
            if os.path.normpath(jail_path) == os.path.join(paths['jails'], name, 'root'):
                ids[name] = jid
        return ids

    async def _jail_disk_usage(self, config):
        """Bytes used by each jail dataset from one zfs list, or {} when unreadable."""
        dataset = bastille_paths(config['pool']).get('jails_dataset') if config.get('pool') else None
        if not dataset:
            return {}
        try:
            result = await run(
                '/sbin/zfs', 'list', '-Hp', '-t', 'filesystem', '-d', '1', '-o', 'name,used',
                dataset, check=False, encoding='utf8',
            )
        except OSError:
            return {}
        if result.returncode:
            return {}
        usage = {}
        prefix = f'{dataset}/'
        for line in result.stdout.splitlines():
            fields = line.split('\t')
            if len(fields) != 2 or not fields[0].startswith(prefix):
                continue
            name = fields[0][len(prefix):]
            if '/' in name or not JAIL_NAME.fullmatch(name):
                continue
            try:
                usage[name] = int(fields[1])
            except ValueError:
                continue
        return usage

    @staticmethod
    def _parse_live_addresses(output):
        """Addresses a running VNET jail reports for itself, as `bastille list` reads them.

        Loopback and link-local entries are dropped, and anything that does not parse as
        an address is ignored rather than trusted: the text comes from inside the jail.
        """
        addresses = {4: [], 6: []}
        interface = ''
        for line in output.splitlines():
            header = IFCONFIG_INTERFACE_LINE.match(line)
            if header:
                interface = header.group('name')
                continue
            match = IFCONFIG_ADDRESS_LINE.match(line)
            if not match:
                continue
            family = 6 if match.group('family') == 'inet6' else 4
            value = match.group('value').split('%', 1)[0]
            tokens = match.group('rest').split()
            if '/' not in value:
                marker = 'netmask' if family == 4 else 'prefixlen'
                try:
                    prefix_value = tokens[tokens.index(marker) + 1]
                except (ValueError, IndexError):
                    prefix_value = None
                if prefix_value is not None:
                    try:
                        if family == 6:
                            prefix = int(prefix_value)
                        elif prefix_value.lower().startswith('0x'):
                            prefix = bin(int(prefix_value, 16)).count('1')
                        else:
                            prefix = ipaddress.IPv4Network(f'0.0.0.0/{prefix_value}').prefixlen
                        value = f'{value}/{prefix}'
                    except ValueError:
                        pass
            try:
                parsed = ipaddress.ip_interface(value)
            except ValueError:
                continue
            if parsed.version != family or parsed.ip.is_loopback or parsed.ip.is_link_local:
                continue
            rendered = f'{interface}|{parsed}' if interface else str(parsed)
            if rendered not in addresses[family]:
                addresses[family].append(rendered)
        return addresses

    async def _live_jail_addresses(self, jail_name):
        """Read a running VNET jail's addresses from inside it, or None when that fails."""
        try:
            result = await asyncio.wait_for(
                run(
                    '/usr/sbin/jexec', '-l', jail_name, '/sbin/ifconfig', '-a',
                    check=False, encoding='utf8', errors='replace',
                ),
                BASTILLE_LIVE_ADDRESS_TIMEOUT,
            )
        except (OSError, asyncio.TimeoutError, CallError):
            return None
        if result.returncode or not result.stdout:
            return None
        return self._parse_live_addresses(result.stdout[:65536])

    @staticmethod
    def _read_bounded_regular_file(path, required=True):
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            if not required:
                return ''
            raise CallError(f'Required Bastille jail configuration {path!r} is missing.')
        except OSError as error:
            raise CallError(f'Unable to inspect Bastille jail configuration {path!r}: {error}')

        if not stat.S_ISREG(metadata.st_mode):
            raise CallError(f'Bastille jail configuration {path!r} is not a regular file.')
        if metadata.st_size > MAX_JAIL_CONFIG_SIZE:
            raise CallError(f'Bastille jail configuration {path!r} is unexpectedly large.')
        try:
            return Path(path).read_text(encoding='utf8')
        except (OSError, UnicodeDecodeError) as error:
            raise CallError(f'Unable to read Bastille jail configuration {path!r}: {error}')

    @staticmethod
    def _validate_generated_rc(config, enabled):
        try:
            metadata = os.lstat(RC_CONFIG_PATH)
            content = Path(RC_CONFIG_PATH).read_text(encoding='utf8')
        except (FileNotFoundError, OSError, UnicodeDecodeError) as error:
            raise CallError(f'Unable to verify generated Bastille rc configuration: {error}')
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_JAIL_CONFIG_SIZE:
            raise CallError('Generated Bastille rc configuration is unsafe or unexpectedly large.')

        expected = {
            'bastille_enable': f'bastille_enable="{"YES" if enabled else "NO"}"',
        }
        if config.get('pool'):
            paths = bastille_paths(config['pool'])
            expected.update({
                'bastille_conf': f'bastille_conf="{paths["config_file"]}"',
                'bastille_env': f'bastille_env="BASTILLE_CONFIG={paths["config_file"]}"',
                'bastille_jailsdir': f'bastille_jailsdir="{paths["jails"]}"',
                'bastille_startup_delay': (
                    f'bastille_startup_delay="{config["startup_delay"]}"'
                ),
                'bastille_parallel_limit': (
                    f'bastille_parallel_limit="{config["parallel_limit"]}"'
                ),
            })

        lines = content.splitlines()
        for variable in (
            'bastille_enable', 'bastille_conf', 'bastille_env', 'bastille_jailsdir',
            'bastille_startup_delay', 'bastille_parallel_limit',
        ):
            candidates = [candidate for candidate in lines if candidate.startswith(f'{variable}=')]
            expected_line = expected.get(variable)
            if candidates != ([expected_line] if expected_line is not None else []):
                raise CallError(
                    f'Generated Bastille rc configuration did not apply {variable!r} safely.'
                )

        # the internal development record: the same etc group renders the CLI pointer into the
        # administrator's bastille.conf; verify it the same way. Applying the pointer
        # again must change nothing: exactly one block, for the configured pool or
        # for no pool (#539). No live file at all means bastille is not installed, which
        # _validate_package_capability reports on its own.
        try:
            metadata = os.lstat(BASTILLE_DEFAULT_CONFIG)
        except FileNotFoundError:
            return
        except OSError as error:
            raise CallError(f'Unable to verify the bastille command-line configuration: {error}')
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_JAIL_CONFIG_SIZE:
            raise CallError('The bastille command-line configuration is not a plain file.')
        try:
            pointer = Path(BASTILLE_DEFAULT_CONFIG).read_text(encoding='utf8')
        except (OSError, UnicodeDecodeError) as error:
            raise CallError(f'Unable to verify the bastille command-line configuration: {error}')
        if apply_config_pointer(pointer, config.get('pool') or None) != pointer:
            raise CallError(
                'Generated Bastille rc configuration did not apply the command-line pool '
                'pointer safely.'
            )

    async def _generate_and_validate_rc(self, config, enabled):
        await self.middleware.call('etc.generate', 'rc')
        self._validate_generated_rc(config, enabled)

    @staticmethod
    def _normalize_address(value, family):
        value = value.strip().strip('"\'')
        dynamic_values = {'none', 'dhcp', 'syncdhcp', 'syncedhcp', 'accept_rtadv'}
        if not value or value.lower() in dynamic_values:
            return None

        interface = ''
        if '|' in value:
            interface, value = value.rsplit('|', 1)
            interface = interface.strip()
            value = value.strip()
        if value.lower() in dynamic_values:
            return None
        try:
            address = ipaddress.ip_interface(value)
        except ValueError as error:
            raise CallError(f'Unable to interpret Bastille jail address {value!r}: {error}')
        if address.version != family:
            raise CallError(
                f'Bastille jail address {value!r} does not match IPv{family} configuration.'
            )
        return f'{interface}|{address}' if interface else str(address)

    @staticmethod
    def _rc_address_with_prefix(tokens, marker_index, family):
        if marker_index + 1 >= len(tokens):
            return None
        address = tokens[marker_index + 1]
        if '/' in address:
            return address

        tail = tokens[marker_index + 2:]
        marker = 'netmask' if family == 4 else 'prefixlen'
        try:
            prefix_value = tail[tail.index(marker) + 1]
        except (ValueError, IndexError):
            return address

        if family == 6:
            try:
                prefix = int(prefix_value)
            except ValueError:
                return address
            return f'{address}/{prefix}'

        try:
            if prefix_value.lower().startswith('0x'):
                mask = int(prefix_value, 16)
                if mask < 0 or mask > 0xffffffff:
                    return address
                bits = f'{mask:032b}'
                if '01' in bits:
                    return address
                prefix = bits.count('1')
            else:
                prefix = ipaddress.IPv4Network(
                    f'0.0.0.0/{prefix_value}', strict=False
                ).prefixlen
        except ValueError:
            return address
        return f'{address}/{prefix}'

    @classmethod
    def _extract_jail_addresses(cls, jail_config, rc_config):
        addresses = {4: [], 6: []}
        for match in JAIL_CONFIG_ADDRESS.finditer(jail_config):
            family = 4 if match.group('family') == 'ip4' else 6
            for value in match.group('value').strip().strip('"\'').split(','):
                address = cls._normalize_address(value, family)
                if address and address not in addresses[family]:
                    addresses[family].append(address)

        for match in RC_CONFIG_INTERFACE.finditer(rc_config):
            try:
                tokens = shlex.split(match.group('value'))
            except ValueError:
                continue
            # the internal development record: `bastille create ... DHCP` writes
            # ifconfig_vnet0="SYNCDHCP" and SLAAC writes "inet6 ... accept_rtadv". Neither
            # carries an address, so the configuration is reported as the dynamic method it
            # names rather than as nothing at all.
            lowered = {token.lower() for token in tokens}
            if lowered & {'dhcp', 'syncdhcp'} and 'DHCP' not in addresses[4]:
                addresses[4].append('DHCP')
            if 'accept_rtadv' in lowered and 'SLAAC' not in addresses[6]:
                addresses[6].append('SLAAC')
            for family, marker in ((4, 'inet'), (6, 'inet6')):
                if marker not in tokens:
                    continue
                marker_index = tokens.index(marker)
                # rc.conf may put ifconfig flags between the family and the address
                # ("inet6 -ifdisabled accept_rtadv" is how bastille spells SLAAC); a
                # flag is never an address, so it must not fail the whole jail.
                tail = tokens[marker_index + 1:]
                while tail and tail[0].startswith('-'):
                    tail = tail[1:]
                value = cls._rc_address_with_prefix(
                    tokens[:marker_index + 1] + tail, marker_index, family
                )
                address = cls._normalize_address(value or '', family)
                if address and address not in addresses[family]:
                    addresses[family].append(address)
        return addresses

    @staticmethod
    def _extract_release(fstab, paths, jail_root):
        expected_destination = os.path.join(jail_root, '.bastille')
        releases_root = os.path.normpath(paths['releases'])
        for line in fstab.splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            try:
                fields = shlex.split(line)
            except ValueError:
                continue
            if len(fields) < 3 or fields[2] != 'nullfs':
                continue
            source = os.path.normpath(fields[0])
            destination = os.path.normpath(fields[1])
            if os.path.dirname(source) != releases_root or destination != expected_destination:
                continue
            release = os.path.basename(source)
            if FREEBSD_RELEASE.fullmatch(release):
                return release
        return None

    @staticmethod
    def _selected_interfaces(addresses):
        interfaces = set()
        for family_addresses in addresses.values():
            for address in family_addresses:
                if '|' in address:
                    interface, _ = address.split('|', 1)
                    if interface:
                        interfaces.add(interface)
        return ','.join(sorted(interfaces))

    @staticmethod
    def _boot_enabled(value):
        if value is None:
            return None
        value = value.lower()
        if value in {'yes', 'on', 'true', '1'}:
            return True
        if value in {'no', 'off', 'false', '0'}:
            return False
        raise CallError(f'Unable to interpret Bastille boot setting {value!r}.')

    @filterable
    async def query(self, filters=None, options=None):
        """List every Bastille jail on the configured pool, read-only.

        the internal development record: middleware observes jails and the bastille CLI manages
        them. A row carries what `bastille list all` knows plus live figures
        (the internal development record). ``operable`` is one cheap identity check -- a real
        directory below the pool's jails dataset whose jail.conf keeps its root inside
        it -- so a symlinked or foreign path is never treated as a jail;
        ``validation_error`` says why when the check fails.
        """
        config = await self._raw_config()
        if not config.get('pool'):
            return filter_list([], filters or [], options or {})

        await self._validate_configured_row(config)
        paths = bastille_paths(config['pool'])
        try:
            with os.scandir(paths['jails']) as entries:
                jail_directories = sorted(entries, key=lambda entry: entry.name)
        except OSError as error:
            raise CallError(f'Unable to inspect the Bastille jail directory: {error}')

        try:
            running = set(await self._running_jails(config, strict=True))
            running_error = None
        except CallError as error:
            running = None
            running_error = error.errmsg

        # Both tolerate an unreadable command; a jail without a jid or a disk figure is
        # still listed.
        running_ids = await self._running_jail_ids(config) if running else {}
        disk_usage = await self._jail_disk_usage(config)

        jails = []
        for entry in jail_directories:
            if not JAIL_NAME.fullmatch(entry.name):
                continue
            if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                continue
            jail_config_path = os.path.join(entry.path, 'jail.conf')
            if not os.path.lexists(jail_config_path):
                continue

            validation_error = None
            jail_config = ''
            try:
                await self._validate_jail_identity(config, entry.name)
                operable = True
            except CallError as error:
                operable = False
                validation_error = error.errmsg

            try:
                jail_config = self._read_bounded_regular_file(jail_config_path)
                rc_config = self._read_bounded_regular_file(
                    os.path.join(entry.path, 'root', 'etc', 'rc.conf'), required=False
                )
                settings = self._read_bounded_regular_file(
                    os.path.join(entry.path, 'settings.conf'), required=False
                )
                fstab = self._read_bounded_regular_file(
                    os.path.join(entry.path, 'fstab'), required=False
                )
                addresses = self._extract_jail_addresses(jail_config, rc_config)
                release = self._extract_release(
                    fstab, paths, os.path.join(entry.path, 'root')
                )
                boot = self._boot_enabled(self._setting_value(settings, 'boot'))
            except CallError as error:
                addresses = {4: [], 6: []}
                release = None
                boot = None
                validation_error = validation_error or error.errmsg

            state = 'UNKNOWN' if running is None else ('up' if entry.name in running else 'down')
            # A running VNET jail (static or DHCP) reports the addresses it actually
            # holds; a stopped one reports what it is configured for.
            jid = running_ids.get(entry.name) if state == 'up' else None
            address_source = 'config'
            if state == 'up' and operable and VNET_DIRECTIVE.search(jail_config):
                live = await self._live_jail_addresses(entry.name)
                if live is not None and (live[4] or live[6]):
                    addresses = live
                    address_source = 'live'
            jails.append({
                'id': entry.name,
                'name': entry.name,
                'engine': 'bastille',
                'state': state,
                'jid': jid,
                'ip4_addr': ','.join(addresses[4]),
                'ip6_addr': ','.join(addresses[6]),
                'address_source': address_source,
                'path': os.path.join(entry.path, 'root'),
                'release': release,
                'interface': self._selected_interfaces(addresses),
                'boot': boot,
                'disk_used': disk_usage.get(entry.name),
                'operable': operable,
                'validation_error': validation_error,
                'running_error': running_error,
            })

        return filter_list(jails, filters or [], options or {})

    async def _dataset_used_bytes(self, dataset):
        """Return one dataset's exact byte usage, or None when it cannot be read."""
        result = await run(
            '/sbin/zfs', 'get', '-Hp', '-o', 'value', 'used', dataset,
            check=False, encoding='utf8',
        )
        if result.returncode:
            return None
        try:
            return int(result.stdout.strip())
        except ValueError:
            raise CallError(f'Unable to interpret the size of dataset {dataset!r}.')

    @accepts()
    async def releases(self):
        """Report each bootstrapped release with the jails on it and its disk cost.

        Read-only (the internal development record): releases are bootstrapped and destroyed with
        the bastille CLI. Consumers are read back from ``query`` so the two views can
        never disagree.
        """
        config = await self._lifecycle_config()
        paths = bastille_paths(config['pool'])
        jails = await self.query()
        try:
            with os.scandir(paths['releases']) as entries:
                names = sorted(
                    (
                        entry.name for entry in entries
                        if FREEBSD_RELEASE.fullmatch(entry.name)
                        and not entry.is_symlink() and entry.is_dir(follow_symlinks=False)
                    ),
                    key=self._release_sort_key, reverse=True,
                )
        except OSError as error:
            raise CallError(f'Unable to inspect Bastille releases: {error}')

        releases = []
        for name in names:
            specs = self._release_dataset_specs(config['pool'], name)
            releases.append({
                'name': name,
                'consumers': sorted(jail['name'] for jail in jails if jail['release'] == name),
                'used_bytes': await self._dataset_used_bytes(specs[1][0]),
                'cache_bytes': await self._dataset_used_bytes(specs[0][0]),
            })
        return releases

    @staticmethod
    def _release_sort_key(release):
        major, _, remainder = release.partition('.')
        return (int(major), int(remainder.split('-', 1)[0]), release)

    @staticmethod
    def _console_log_tail(path, limit):
        """Read only a bounded tail of an exact regular log, never a symlink/device."""
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as log:
                metadata = os.fstat(log.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise CallError('Bastille console log is not a single regular file.')
                offset = max(0, metadata.st_size - limit)
                log.seek(offset)
                content = log.read(limit).decode('utf8', 'replace')
                return {'content': content, 'truncated': offset > 0}
        except OSError as error:
            raise CallError(f'Unable to read the Bastille console log: {error.strerror}') from error

    @lock('bastille_lifecycle_internal')
    @accepts(
        Str('name', required=True, empty=False, validators=[Match(JAIL_NAME.pattern)]),
        Int('limit', default=65536, validators=[Range(min=1, max=MAX_CONSOLE_LOG_BYTES)]),
    )
    async def logs(self, name, limit):
        """Return a bounded console-log tail for one identified jail."""
        config = await self._lifecycle_config()
        paths = bastille_paths(config['pool'])
        await self._validate_jail_identity(config, name)
        # A jail has no console log until it has been started once: an empty log, not a
        # fault.
        path = self._validate_console_log(paths, name, required=False)
        if not os.path.lexists(path):
            return {'name': name, 'content': '', 'truncated': False}
        path = self._validate_console_log(paths, name)
        result = await self.middleware.run_in_thread(self._console_log_tail, path, limit)
        return {'name': name, **result}

    @private
    async def start_after_export(self, name):
        """Restart one jail that stop_for_pool stopped for a pool export that then failed.

        the internal development record left this as the one place middleware drove a jail --
        undoing a stop it performed itself. #475 adds start, stop and restart beside it;
        everything else about a jail is still the bastille CLI's.
        """
        if not JAIL_NAME.fullmatch(name) or name.lower() in RESERVED_BASTILLE_TARGETS:
            raise CallError('Bastille jail name is invalid.')
        await self._run_bastille_lifecycle('start', name)
        return True

    @staticmethod
    async def _run_bastille_lifecycle(action, name):
        result = await run(
            BASTILLE_PATH, action, name, check=False, encoding='utf8', errors='replace'
        )
        if result.returncode:
            detail = (result.stderr or result.stdout or '').strip()[:MAX_COMMAND_ERROR_SIZE]
            raise CallError(f'bastille {action} {name} failed: {detail or "no error text"}')
        return result

    async def _jail_action(self, name, action):
        """Start, stop or restart one jail the way `bastille <action> <name>` would.

        the internal development record: identity only (tier 1), never ownership. A jail
        administered with the CLI -- rdr rules, rctl limits, its own fstab lines -- is the
        ordinary jail now, and operating it writes nothing to it. The CLI is the whole
        mechanism; middleware only checks from jls that it did what was asked.
        """
        config = await self._lifecycle_config()
        await self._validate_jail_identity(config, name)
        expected_running = action != 'stop'
        await self._run_bastille_lifecycle(action, name)
        if (name in await self._running_jails(config, strict=True)) != expected_running:
            raise CallError(
                f'Bastille {action} did not leave jail {name!r} '
                f'{"running" if expected_running else "stopped"}.'
            )
        return True

    @lock('bastille_lifecycle_internal')
    @accepts(Str('name', required=True, empty=False, validators=[Match(JAIL_NAME.pattern)]))
    @job(lock='bastille_jail_lifecycle')
    async def start(self, job, name):
        """Start one Bastille jail."""
        return await self._jail_action(name, 'start')

    @lock('bastille_lifecycle_internal')
    @accepts(Str('name', required=True, empty=False, validators=[Match(JAIL_NAME.pattern)]))
    @job(lock='bastille_jail_lifecycle')
    async def stop(self, job, name):
        """Stop one Bastille jail."""
        return await self._jail_action(name, 'stop')

    @lock('bastille_lifecycle_internal')
    @accepts(Str('name', required=True, empty=False, validators=[Match(JAIL_NAME.pattern)]))
    @job(lock='bastille_jail_lifecycle')
    async def restart(self, job, name):
        """Restart one Bastille jail."""
        return await self._jail_action(name, 'restart')

    @accepts()
    async def config(self):
        config = await self._raw_config()
        service = await self._service_row()
        configuration_valid, configuration_error = await self._configuration_status(config)
        try:
            running = await self._running_jails(config)
            running_count = len(running)
            running_error = None
        except CallError as error:
            running = []
            running_count = None
            running_error = error.errmsg
        config.update({
            'installed': (
                os.access(BASTILLE_PATH, os.X_OK) and
                os.access(BASTILLE_RC_PATH, os.X_OK) and
                self._package_capability_valid()
            ),
            'configured': bool(config['pool']),
            'configuration_valid': configuration_valid,
            'configuration_error': configuration_error,
            'enabled': bool(service and service['srv_enable']),
            'running_jails': running,
            'running_jail_count': running_count,
            'running_jails_error': running_error,
            'paths': bastille_paths(config['pool']) if config['pool'] else None,
        })
        return config

    @private
    async def rc_config(self):
        config = await self._raw_config()
        service = await self._service_row()
        configuration_valid, _ = await self._configuration_status(config)
        return {
            **config,
            'configuration_valid': configuration_valid,
            'enabled': bool(service and service['srv_enable']),
            'switching_pool': (
                getattr(self, '_pool_switch_in_progress', False) or
                self._pool_is_unavailable(config.get('pool'))
            ),
        }

    @private
    async def validate_configured(self):
        return await self._validate_configured_row(await self._raw_config())

    @private
    async def validate_startable(self):
        # the internal development record: the jails are the rc script's and the CLI's business;
        # middleware only vouches for its own configuration.
        await self._lifecycle_config()
        return True

    @private
    async def rc_preflight(self, action):
        if action not in {'start', 'stop', 'restart'}:
            raise CallError(f'Unsupported Bastille rc action {action!r}.')
        config = await self._raw_config()
        if not config.get('pool'):
            return True
        await self._validate_configured_row(config)
        self._validate_package_capability()
        service = await self._service_row()
        enabled = bool(service and service['srv_enable']) and not (
            getattr(self, '_pool_switch_in_progress', False) or
            self._pool_is_unavailable(config.get('pool'))
        )
        self._validate_generated_rc(config, enabled)
        if os.path.lexists(bastille_paths(config['pool'])['pf_config']):
            raise CallError('Bastille rc lifecycle requires its PF configuration path to be absent.')
        return True

    @private
    async def rc_postflight(self, action):
        if action not in {'start', 'stop', 'restart'}:
            raise CallError(f'Unsupported Bastille rc action {action!r}.')
        config = await self._raw_config()
        if not config.get('pool'):
            return True
        if action in {'start', 'restart'}:
            # The rc script starts every jail marked boot=on; say so when one did not
            # come up, the way a failed service start should.
            missing = sorted(
                jail['name'] for jail in await self.query()
                if jail['boot'] and jail['state'] != 'up'
            )
            if missing:
                raise CallError(
                    f'Bastille rc start left boot-enabled jail(s) stopped: {", ".join(missing)}.'
                )
        return True

    @private
    async def verify_current_rc(self):
        config = await self._raw_config()
        service = await self._service_row()
        enabled = bool(service and service['srv_enable']) and not (
            getattr(self, '_pool_switch_in_progress', False) or
            self._pool_is_unavailable(config.get('pool'))
        )
        self._validate_generated_rc(config, enabled)
        return True

    @private
    async def disable_service(self):
        await self._disable_service_row()
        config = await self._raw_config()
        await self._generate_and_validate_rc(config, False)
        return True

    @private
    async def running_jails(self):
        return await self._running_jails(await self._raw_config())

    @private
    async def running_jails_strict(self):
        return await self._running_jails(await self._raw_config(), strict=True)

    @private
    @lock('bastille_lifecycle_internal')
    async def stop_for_pool(self, pool_name, snapshot_running=False):
        config = await self._raw_config()
        if config.get('pool') != pool_name:
            return False
        await self.rc_preflight('stop')

        unavailable = self._unavailable_pool_names()
        unavailable.add(pool_name)
        try:
            if snapshot_running:
                # Snapshot and stop share the lifecycle lock, so a jail started
                # concurrently cannot be stopped below and then omitted from failed-export
                # recovery. Only the non-destructive export path asks for this; each
                # attempt re-reads the live set rather than trusting an earlier one.
                self._pool_stop_runtime_names()[pool_name] = list(
                    await self._running_jails(config, strict=True)
                )
            # Keep rc startup disabled for the complete period in which the active store is
            # unavailable. Calling service.stop here would reacquire this non-reentrant lock.
            await self._generate_and_validate_rc(config, False)
            result = await freebsd_service('bastille', 'forcestop')
            if result.returncode:
                raise CallError('The Bastille rc service failed to stop every Bastille-owned jail.')
            running = await self._running_jails(config, strict=True)
            if running:
                raise CallError(
                    f'Unable to make Bastille storage unavailable while jails are running: '
                    f'{", ".join(running)}.'
                )
        except BaseException as error:
            try:
                service = await self._service_row()
                unavailable.discard(pool_name)
                await self._generate_and_validate_rc(
                    config, bool(service and service['srv_enable'])
                )
            except Exception as restore_error:
                unavailable.add(pool_name)
                with contextlib.suppress(Exception):
                    await self._generate_and_validate_rc(config, False)
                raise CallError(
                    f'{getattr(error, "errmsg", str(error))} Bastille rc state could not be '
                    f'restored safely: {restore_error}'
                ) from error
            raise
        return True

    @private
    async def pool_stop_running(self, pool_name):
        names = self._pool_stop_runtime_names().get(pool_name)
        return list(names) if names is not None else None

    @private
    @lock('bastille_lifecycle_internal')
    async def pool_available(self, pool_name=None):
        config = await self._raw_config()
        if pool_name is not None and config.get('pool') != pool_name:
            # An imported/unlocked retained store is no longer part of an earlier transition
            # once another store is active. Do not let its stale marker block selecting it later.
            self._unavailable_pool_names().discard(pool_name)
            return {'matched': False, 'enabled': False}
        if not config.get('pool'):
            return {'matched': False, 'enabled': False}

        unavailable = self._unavailable_pool_names()
        unavailable.add(config['pool'])
        try:
            await self._validate_configured_row(config)
            await self._generate_and_validate_rc(config, False)
            service = await self._service_row()
            enabled = bool(service and service['srv_enable'])
            unavailable.discard(config['pool'])
            await self._generate_and_validate_rc(config, enabled)
        except BaseException:
            unavailable.add(config['pool'])
            with contextlib.suppress(Exception):
                await self._generate_and_validate_rc(config, False)
            raise
        self._pool_stop_runtime_names().pop(config['pool'], None)
        return {'matched': True, 'enabled': enabled}

    @private
    @lock('bastille_lifecycle_internal')
    async def deactivate_pool(self, pool_name):
        old = await self._raw_config()
        if old.get('pool') != pool_name:
            return False

        running = await self._running_jails(old, strict=True)
        if running:
            raise CallError(
                f'Stop all Bastille jails before clearing its active pool: {", ".join(running)}.'
            )

        self._pool_switch_in_progress = True
        datastore_updated = False
        try:
            await self._generate_and_validate_rc(old, False)
            new = {
                'pool': None,
                'startup_delay': old['startup_delay'],
                'parallel_limit': old['parallel_limit'],
            }
            await self.middleware.call(
                'datastore.update', 'services.bastille', old['id'], new,
                {'prefix': 'bastille_'},
            )
            datastore_updated = True
            await self._generate_and_validate_rc(new, False)
            # Leave the administrator's own settings in place; only our block changes, to
            # the one that stops an unaided bastille for want of a pool (#539).
            self._write_cli_config_pointer(None)
        except BaseException as error:
            rollback_errors = []
            if datastore_updated:
                try:
                    await self.middleware.call(
                        'datastore.update', 'services.bastille', old['id'], {
                            'pool': old['pool'],
                            'startup_delay': old['startup_delay'],
                            'parallel_limit': old['parallel_limit'],
                        }, {'prefix': 'bastille_'},
                    )
                except Exception as rollback_error:  # noqa: BLE001
                    rollback_errors.append(f'database restore failed: {rollback_error}')
            try:
                await self._generate_and_validate_rc(old, False)
            except Exception as rollback_error:  # noqa: BLE001
                rollback_errors.append(f'rc restore failed: {rollback_error}')
            try:
                self._write_cli_config_pointer(old['pool'])
            except Exception as rollback_error:  # noqa: BLE001
                rollback_errors.append(f'command-line config restore failed: {rollback_error}')
            if rollback_errors:
                raise CallError(
                    f'{getattr(error, "errmsg", str(error))} Pool deactivation rollback failed: '
                    f'{"; ".join(rollback_errors)}'
                ) from error
            self._pool_switch_in_progress = False
            raise

        self._pool_switch_in_progress = False
        self._unavailable_pool_names().discard(pool_name)
        return True

    async def _create_datasets(self, pool_name, created):
        for dataset, owner in bastille_dataset_specs(pool_name):
            await self.middleware.call('zfs.dataset.create', {
                'name': dataset,
                'properties': {
                    'atime': 'off',
                    'compression': 'lz4',
                    MANAGED_PROPERTY: owner,
                },
            })
            created.append(dataset)
            await self.middleware.call('zfs.dataset.mount', dataset)
            os.chmod(f'/mnt/{dataset}', 0o750)

    async def _dataset_exists(self, pool_name):
        dataset = bastille_paths(pool_name)['dataset']
        return bool(await self.middleware.call(
            'zfs.dataset.query', [('id', '=', dataset)]
        ))

    async def _prepare_switch_target(self, pool_name, created):
        if await self._dataset_exists(pool_name):
            await self._validate_managed_tree(pool_name)
            await self._validate_mounted_tree(pool_name)
            running = await self._running_jails({'pool': pool_name}, strict=True)
            if running:
                raise CallError(
                    f'Stop all Bastille jails in target pool {pool_name!r} before selecting it: '
                    f'{", ".join(running)}.'
                )
        else:
            await self._create_datasets(pool_name, created)

    async def _disable_service_row(self):
        service = await self._service_row()
        if service and service['srv_enable']:
            await self.middleware.call(
                'datastore.update', 'services.services', service['id'], {'srv_enable': False}
            )

    def _read_cli_config_pointer(self):
        """Read the default bastille.conf, refusing anything but a plain regular file."""
        try:
            metadata = os.lstat(BASTILLE_DEFAULT_CONFIG)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise CallError(f'Unable to inspect {BASTILLE_DEFAULT_CONFIG!r}: {error}')
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise CallError(
                f'{BASTILLE_DEFAULT_CONFIG} is not a regular file; refusing to rewrite it.'
            )
        if metadata.st_size > MAX_JAIL_CONFIG_SIZE:
            raise CallError(f'{BASTILLE_DEFAULT_CONFIG} is too large to manage safely.')
        return self._read_bounded_regular_file(BASTILLE_DEFAULT_CONFIG)

    def _write_cli_config_pointer(self, pool):
        """Make an unaided `bastille` find the configured pool, or stop it when there is none.

        the internal development record: `iocage list` works in any shell because iocage discovers its
        pool from a ZFS property. bastille has no discovery -- it reads exactly one file,
        BASTILLE_DEFAULT_CONFIG -- so a shell that had not exported BASTILLE_CONFIG read
        stock defaults with ZFS disabled and reported no jails, while jls showed them
        running. The fix is a managed include, not a copy: one source of truth remains
        the pool config this service already generates.

        The file is the administrator's (the port installs only bastille.conf.sample,
        and bastille itself creates the live file from it), which is what makes owning a
        block inside it legitimate -- the internal development record assumed the opposite.
        """
        existing = self._read_cli_config_pointer()
        if pool is None and existing is None:
            # No live file to rewrite; the seed may still carry a block from an earlier boot.
            self._sync_cli_config_seed()
            # Nothing to stop pointing at. Removal must never depend on the package
            # still being installed: deactivate_pool runs while a pool is being
            # exported, and failing there would block the export itself.
            return False
        if pool is not None:
            # The package owns this directory. If it is absent bastille is not installed,
            # and writing a config for it would be inventing state -- as well as letting
            # a caller create /usr/local/etc on a machine that has no bastille at all.
            directory = os.path.dirname(BASTILLE_DEFAULT_CONFIG)
            if not os.path.isdir(directory):
                raise CallError(f'{directory} does not exist; Bastille is not installed.')

        if existing is None:
            # bastille creates this from the sample on first run; do the same, so an
            # administrator who never ran it still gets the documented defaults.
            base = ''
            with contextlib.suppress(FileNotFoundError):
                if stat.S_ISREG(os.lstat(BASTILLE_SAMPLE_CONFIG).st_mode):
                    base = Path(BASTILLE_SAMPLE_CONFIG).read_text(encoding='utf8')
            mode = 0o644
        else:
            base = existing
            mode = stat.S_IMODE(os.lstat(BASTILLE_DEFAULT_CONFIG).st_mode)

        updated = apply_config_pointer(base, pool)
        if existing is not None and updated == existing:
            # The live file is already right; boxes configured before the seed was kept in
            # step still need it carried over, so the sync is not tied to a rewrite.
            self._sync_cli_config_seed()
            return False
        if existing is not None:
            # Keep one copy of the administrator's own lines from before middleware first
            # wrote a pool into the file. The rc group renders the no-pool block at boot
            # (#539), so by now it may already be there; it is not theirs to keep.
            backup = f'{BASTILLE_DEFAULT_CONFIG}.freecore-backup'
            if not os.path.lexists(backup):
                atomic_write(backup, strip_config_pointer(existing), mode)
        atomic_write(BASTILLE_DEFAULT_CONFIG, updated, mode)
        self._sync_cli_config_seed()
        return True

    def _sync_cli_config_seed(self):
        """Carry the live bastille.conf into the seed /etc is rebuilt from at boot.

        the internal development record: /etc is a tmpfs seeded from /conf/base/etc on every boot and
        /usr/local/etc is /etc/local, so a block written only to BASTILLE_DEFAULT_CONFIG was
        gone after the first reboot and an unaided `bastille` read stock defaults again --
        no releases, no jails -- while the rc service (which gets bastille_conf from rc.conf)
        kept starting them. ix-savehostid keeps /etc/hostid across boots the same way.

        The seed mirrors the whole live file, so an administrator's own edits survive a
        reboot as well, which is what they expect of a file they own. When the live file is
        gone (rollback of a first configuration) only our block is stripped from the seed.
        """
        if not os.path.isdir(os.path.dirname(BASTILLE_BASE_CONFIG)):
            return
        try:
            live = os.lstat(BASTILLE_DEFAULT_CONFIG)
        except FileNotFoundError:
            seed = self._read_bounded_regular_file(BASTILLE_BASE_CONFIG, required=False)
            stripped = strip_config_pointer(seed)
            if seed and stripped != seed:
                atomic_write(
                    BASTILLE_BASE_CONFIG, stripped,
                    stat.S_IMODE(os.lstat(BASTILLE_BASE_CONFIG).st_mode),
                )
            return
        if not stat.S_ISREG(live.st_mode):
            return
        content = self._read_bounded_regular_file(BASTILLE_DEFAULT_CONFIG)
        if self._read_bounded_regular_file(BASTILLE_BASE_CONFIG, required=False) == content:
            return
        atomic_write(BASTILLE_BASE_CONFIG, content, stat.S_IMODE(live.st_mode))

    async def _restore_failed_configure(
        self, old, paths, created, old_file_exists, old_content, datastore_updated,
        old_service_enabled, old_pointer=None, pointer_written=False,
    ):
        errors = []
        self._pool_switch_in_progress = True

        if pointer_written:
            try:
                if old_pointer is None:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(BASTILLE_DEFAULT_CONFIG)
                else:
                    atomic_write(BASTILLE_DEFAULT_CONFIG, old_pointer, 0o644)
                self._sync_cli_config_seed()
            except Exception as error:  # noqa: BLE001 -- collect every rollback failure
                errors.append(f'command-line config restore failed: {error}')

        if datastore_updated:
            try:
                await self.middleware.call(
                    'datastore.update', 'services.bastille', old['id'], {
                        'pool': old['pool'],
                        'startup_delay': old['startup_delay'],
                        'parallel_limit': old['parallel_limit'],
                    }, {'prefix': 'bastille_'},
                )
            except Exception as error:  # noqa: BLE001 -- collect every rollback failure
                errors.append(f'database restore failed: {error}')

        try:
            if created:
                await self.middleware.call(
                    'zfs.dataset.delete', paths['dataset'],
                    {'force': True, 'recursive': True},
                )
            elif old_content is not None:
                atomic_write(paths['config_file'], old_content)
            elif not old_file_exists:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(paths['config_file'])
        except Exception as error:  # noqa: BLE001 -- collect every rollback failure
            errors.append(f'target-store restore failed: {error}')

        if not old['pool']:
            try:
                await self._disable_service_row()
            except Exception as error:  # noqa: BLE001 -- collect every rollback failure
                errors.append(f'service disable failed: {error}')
            old_service_enabled = False

        try:
            restored = await self._raw_config()
            if any(restored[field] != old[field] for field in ('pool', 'startup_delay', 'parallel_limit')):
                raise CallError('The Bastille database pointer does not match its previous value.')
            if old['pool']:
                await self._validate_configured_row(old)
            await self._generate_and_validate_rc(old, False)
        except Exception as error:  # noqa: BLE001 -- collect every rollback failure
            errors.append(f'fail-closed rc restore failed: {error}')

        if not errors:
            self._pool_switch_in_progress = False
            try:
                await self._generate_and_validate_rc(old, old_service_enabled)
                return []
            except Exception as error:  # noqa: BLE001 -- fall through to persistent disable
                errors.append(f'service-state rc restore failed: {error}')
                self._pool_switch_in_progress = True

        fail_safe_errors = []
        try:
            await self._disable_service_row()
        except Exception as error:  # noqa: BLE001 -- report an unverified fail-safe
            fail_safe_errors.append(f'persistent service disable failed: {error}')

        try:
            current = await self._raw_config()
            await self._generate_and_validate_rc(current, False)
        except Exception as error:  # noqa: BLE001 -- report an unverified fail-safe
            fail_safe_errors.append(f'disabled rc verification failed: {error}')

        if not fail_safe_errors:
            self._pool_switch_in_progress = False
        errors.extend(fail_safe_errors)
        return errors

    @lock('bastille_lifecycle_internal')
    @accepts(Dict(
        'bastille_configure',
        Str('pool', required=True, empty=False, validators=[Match(POOL_NAME.pattern)]),
        Int('startup_delay', default=0, validators=[Range(min=0, max=3600)]),
        Int('parallel_limit', default=1, validators=[Range(min=1, max=64)]),
    ))
    @job(lock='bastille_configure')
    async def configure(self, job, data):
        self._validate_package_capability()
        old = await self._raw_config()
        if self._pool_is_unavailable(data['pool']):
            raise CallError(
                f'Bastille pool {data["pool"]!r} is being locked, exported, or recovered.'
            )
        switching_pool = bool(old['pool'] and old['pool'] != data['pool'])

        if switching_pool:
            try:
                await self._validate_configured_row(old)
            except Exception as error:
                self.logger.warning(
                    'Selecting a replacement for unavailable or invalid Bastille pool %r: %s',
                    old['pool'], error,
                )
            running = await self._running_jails(old, strict=True)
            if running:
                raise CallError(
                    f'Stop all Bastille jails in current pool {old["pool"]!r} before changing '
                    f'pools: {", ".join(running)}.'
                )
            await self._validate_pool(data['pool'], False)
        else:
            await self._validate_pool(data['pool'], False)
            if old['pool']:
                await self._validate_managed_tree(old['pool'])
                await self._validate_mounted_tree(old['pool'])

        service = await self._service_row()
        old_service_enabled = bool(service and service['srv_enable'])
        old_rc_enabled = old_service_enabled and not self._pool_is_unavailable(old.get('pool'))
        target_was_unavailable = self._pool_is_unavailable(data['pool'])
        new = {
            'pool': data['pool'],
            'startup_delay': data['startup_delay'],
            'parallel_limit': data['parallel_limit'],
        }
        created = []
        datastore_updated = False
        paths = bastille_paths(data['pool'])
        old_file_exists = False
        old_content = None
        old_pointer = None
        pointer_written = False
        configuration_started = False
        try:
            if not old['pool']:
                job.set_progress(10, 'Selecting the Bastille dataset hierarchy')
                await self._prepare_switch_target(data['pool'], created)
            elif switching_pool:
                job.set_progress(10, 'Selecting the Bastille dataset hierarchy')
                await self._prepare_switch_target(data['pool'], created)

            old_file_exists = os.path.lexists(paths['config_file'])
            if old_file_exists:
                old_content = self._read_bounded_regular_file(paths['config_file'])
            old_pointer = self._read_cli_config_pointer()

            # Match iocage's active-store semantics: the old tree is retained. Hold rc disabled
            # until its paths, settings, and the middleware pointer all name a verified target.
            self._pool_switch_in_progress = True
            configuration_started = True
            await self._generate_and_validate_rc(old, False)

            job.set_progress(60, 'Writing the appliance-safe Bastille configuration')
            atomic_write(paths['config_file'], render_bastille_config(data['pool']))
            await self._validate_configured_row(new)

            if any(old[field] != new[field] for field in new):
                await self.middleware.call(
                    'datastore.update', 'services.bastille', old['id'], new,
                    {'prefix': 'bastille_'},
                )
                datastore_updated = True
            # Only once the pool config is written and the row verified: the pointer
            # names a target that exists. A pool change repoints it, never leaving it
            # aimed at the old pool. This runs before the rc group is regenerated for
            # the new row (the internal development record renders the same block from there),
            # so the one-time backup of the administrator's untouched file is still
            # taken, and the seed is carried over.
            job.set_progress(80, 'Pointing the bastille command line at the data pool')
            self._write_cli_config_pointer(data['pool'])
            pointer_written = True
            await self._generate_and_validate_rc(new, False)
            self._unavailable_pool_names().discard(data['pool'])
            self._pool_switch_in_progress = False
            service = await self._service_row()
            await self._generate_and_validate_rc(new, bool(service and service['srv_enable']))
        except BaseException as error:
            if target_was_unavailable:
                self._unavailable_pool_names().add(data['pool'])
            else:
                self._unavailable_pool_names().discard(data['pool'])
            if not configuration_started and not created and not datastore_updated:
                raise
            rollback_errors = await self._restore_failed_configure(
                old, paths, created, old_file_exists, old_content, datastore_updated,
                old_rc_enabled, old_pointer, pointer_written,
            )
            if rollback_errors:
                message = getattr(error, 'errmsg', str(error))
                raise CallError(
                    f'{message} Rollback could not be fully verified; Bastille was disabled. '
                    f'{"; ".join(rollback_errors)}'
                ) from error
            raise

        job.set_progress(100, 'Bastille storage and service configuration are ready')
        return await self.config()


class BastilleFSAttachmentDelegate(FSAttachmentDelegate):
    name = 'bastille'
    title = 'Bastille'

    async def query(self, path, enabled, options=None):
        config = await self.middleware.call('bastille.rc_config')
        if not config.get('pool'):
            return []
        if (
            options and options.get('locked') is False and
            not config.get('configuration_valid', False)
        ):
            # Native dataset unlock invokes attachment recovery even when key loading or
            # mounting failed. Preserve its structured failure result until this store is real.
            return []

        mountpoint = bastille_paths(config['pool'])['mountpoint']
        if not (is_child(mountpoint, path) or is_child(path, mountpoint)):
            # the internal development record: what a jail mounts from elsewhere on the pool is
            # the CLI's business, so no dataset outside the store is an attachment of ours.
            return []

        attachment_type = 'boot-enabled' if config['enabled'] else 'runtime-only'
        if enabled:
            attachment_types = [attachment_type]
        else:
            # Pool export records only the ID. Offer both stable IDs after import so the pool
            # framework can restore boot intent without turning a manually-run jail into it.
            attachment_types = ['boot-enabled', 'runtime-only']
        return [
            {
                'id': f'bastille:{kind}',
                'name': 'Bastille',
                'pool': config['pool'],
                'boot_enabled': kind == 'boot-enabled',
            }
            for kind in attachment_types
        ]

    async def stop(self, attachments, snapshot_running=False):
        if attachments:
            # Leave the cascade/delete call shape untouched; only the reversible export
            # toggle asks stop_for_pool to record what it is about to stop.
            extra = [True] if snapshot_running else []
            await self.middleware.call(
                'bastille.stop_for_pool', attachments[0]['pool'], *extra
            )

    async def start(self, attachments):
        if not attachments:
            return
        state = await self.middleware.call('bastille.pool_available', attachments[0]['pool'])
        if state['matched'] and any(attachment['boot_enabled'] for attachment in attachments):
            await self.middleware.call('service.start', 'bastille')

    async def toggle(self, attachments, enabled):
        if not attachments:
            return
        if not enabled:
            attachments[0]['export_stop_attempted'] = True
            await self.stop(attachments, snapshot_running=True)
            if any(attachment['boot_enabled'] for attachment in attachments):
                await self.middleware.call('service.update', 'bastille', {'enable': False})
            return

        state = await self.middleware.call('bastille.pool_available', attachments[0]['pool'])
        if state['matched'] and any(attachment['boot_enabled'] for attachment in attachments):
            await self.middleware.call('service.update', 'bastille', {'enable': True})

    async def rollback_export(self, attachments):
        if not attachments or not attachments[0].get('export_stop_attempted'):
            return False
        previous_running = await self.middleware.call('bastille.pool_stop_running', attachments[0]['pool'])
        if previous_running is None:
            return False
        state = await self.middleware.call('bastille.pool_available', attachments[0]['pool'])
        if not state['matched']:
            return False
        await self.middleware.call('service.update', 'bastille', {
            'enable': any(attachment['boot_enabled'] for attachment in attachments),
        })
        running = set(await self.middleware.call('bastille.running_jails_strict'))
        for name in previous_running:
            if name in running:
                continue
            await self.middleware.call('bastille.start_after_export', name)
        return True

    async def delete(self, attachments):
        if not attachments:
            return
        await self.stop(attachments)
        await self.middleware.call('service.update', 'bastille', {'enable': False})
        await self.middleware.call('bastille.deactivate_pool', attachments[0]['pool'])


async def _bastille_pool_available(middleware, pool, **kwargs):
    pool_name = pool['name'] if pool is not None else None
    state = await middleware.call('bastille.pool_available', pool_name)
    if state['matched'] and state['enabled'] and await middleware.call('system.ready'):
        await middleware.call('service.start', 'bastille')


async def _bastille_datasets_available(middleware, datasets, **kwargs):
    config = await middleware.call('bastille.rc_config')
    dataset_names = {
        dataset['name'] for dataset in datasets
        if isinstance(dataset.get('name'), str) and dataset['name']
    }
    unlocked_pools = {name.split('/', 1)[0] for name in dataset_names}

    # A previously active store can be retained on a pool after another store is selected.
    # Let availability events for those inactive pools clear their stale transition markers.
    for pool_name in unlocked_pools - {config.get('pool')}:
        await middleware.call('bastille.pool_available', pool_name)

    if not config.get('pool') or not config.get('switching_pool'):
        return

    root = bastille_paths(config['pool'])['dataset']
    if any(
        name == root or name.startswith(f'{root}/') or root.startswith(f'{name}/')
        for name in dataset_names
    ):
        # Respect toggle_attachments=False: verify and unblock the store, but do not start it.
        await middleware.call('bastille.pool_available', config['pool'])


async def _bastille_system_event(middleware, event_type, args):
    if args['id'] == 'ready':
        await _bastille_pool_available(middleware, None)


async def setup(middleware):
    await middleware.call(
        'pool.dataset.register_attachment_delegate', BastilleFSAttachmentDelegate(middleware)
    )
    middleware.register_hook('pool.post_import', _bastille_pool_available, sync=True)
    middleware.register_hook('pool.post_unlock', _bastille_pool_available, sync=True)
    middleware.register_hook('dataset.post_unlock', _bastille_datasets_available, sync=True)
    middleware.event_subscribe('system', _bastille_system_event)
