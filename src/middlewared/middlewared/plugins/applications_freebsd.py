import asyncio
import contextlib
import copy
import errno
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import stat
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

import middlewared.sqlalchemy as sa
from middlewared.common.attachment import FSAttachmentDelegate
from middlewared.etc_files import pf as pf_renderer
from middlewared.plugins.applications_.storage import (
    layer_recovery_plan,
    read_layer_ids,
    restore_layer_mountpoints,
)
from middlewared.plugins.applications_.utils import (
    APPLICATION_LABEL,
    CATALOG_RUNTIME_ANNOTATIONS,
    MANAGED_LABEL,
    NETWORK_OWNED_ANNOTATIONS,
    PODMAN_PATH,
    RUNTIME_PF_ACTIVE,
    RUNTIME_READY,
    TRANSACTION_LABEL,
    VOLATILE_RUNROOT,
    application_paths,
    atomic_write,
    lan_conflist_path,
    lan_managed_conflist_path,
    podman_create_args,
    podman_environment,
    public_record,
    render_containers_conf,
    render_lan_conflist,
    render_managed_leg_conflist,
    render_storage_conf,
    temporary_environment_file,
    validate_image_reference,
    validate_mount_target,
)
from middlewared.plugins.applications_ import certificates as app_certificates
from middlewared.plugins.applications_.catalog import (
    CATALOG_FIELDS,
    HOST_ALIAS,
    OPTIONAL_CATALOG_FIELDS,
    compose_extra_hosts,
    image_version,
    installed_catalog_provenance,
)
from middlewared.plugins.applications_.reconfigure import (
    ReconfigureError,
    anything_changed,
    bind_reconfigure,
)
from middlewared.plugins.applications_.registry import image_refusals, inspect_remote_image
from middlewared.schema import Bool, Dict, Int, IPAddr, List, Str, accepts
from middlewared.service import Service, filterable, job, lock, private
from middlewared.service_exception import CallError, ValidationErrors
from middlewared.utils import filter_list, run
from middlewared.utils.path import is_child
from middlewared.validators import Match, Range

APPLICATION_NAME = r'^[a-z0-9][a-z0-9_.-]{0,62}$'
ENVIRONMENT_NAME = r'^[A-Za-z_][A-Za-z0-9_]*$'
ENVIRONMENT_VALUE = r'^[^\x00\r\n]*$'
ANNOTATION_NAME = r'^org\.freebsd\.jail\.[a-z0-9_.-]+$'
ANNOTATION_VALUE = r'^[^\x00\r\n]*$'
# the internal development record: user-defined container labels. The name shape is podman's own
# (OCI annotation keys); the value rules match ENVIRONMENT_VALUE because both end up on a
# command line. `io.freecore.` is refused -- those are our management labels, and query(),
# boot recovery and transaction rollback recognise our containers by them, so a user label
# must never be able to impersonate or shadow one.
LABEL_NAME = r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,253}$'
# the internal development record: the provider runtime options a record may carry, and their bound.
RUNTIME_FIELDS = {'stop_timeout', 'extra_hosts'}
MAX_STOP_TIMEOUT = 3600
LABEL_VALUE = r'^[^\x00\r\n]*$'
RESERVED_LABEL_PREFIX = 'io.freecore.'
PORTAL_PATH = r'^/(?!/)[^\x00\r\n]*$'
DATASET_NAME = r'^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+$'
CONTAINER_ID = r'^[0-9a-f]{64}$'
MANAGED_PROPERTY = 'org.freecore:managedby'
RECORD_SCHEMAS = {2, 3, 4}
# the internal development record: how a LAN attachment names the interface it joins.
LAN_INTERFACE = re.compile(r'^[a-z][a-z0-9.]{1,14}$')
IMAGE_OPERATING_SYSTEMS = {'freebsd', 'linux'}
# the internal development record: where a record came from when it was not a catalog install.
ORIGIN_KINDS = {'byo', 'convert'}
LEGACY_CATALOG_FIELDS = {
    'compose_sha256', 'entry_revision', 'id', 'object_sha256', 'repository',
    'snapshot_sequence', 'source_commit', 'version',
}
LINUX_OSRELEASE_SYSCTL = 'compat.linux.osrelease'
# The kernel module name (not the file) that linux64.ko registers: it is the
# 64-bit Linux ELF brand, and it is the only proof that Linux binaries can run.
LINUX_ELF_MODULE = 'linux64elf'
LINUX_RC_SCRIPT = 'linux'
DEFAULT_SUBNET = '10.88.0.0/16'
DECLARATION_LIMITS = {
    'ports': 256,
    'environment': 128,
    'volumes': 128,
    'annotations': 128,
    'labels': 128,
    # the internal development record: system certificates mounted into the application.
    'certificates': app_certificates.MAX_CERTIFICATES,
}
MAX_RECORD_SIZE = 16 * 1024 * 1024
# the internal development record: the one-shot alerts keyed by application name.
CERTIFICATE_ALERT_CLASSES = (
    'ApplicationsCertificateRenderFailed',
    'ApplicationsCertificateRestartFailed',
)
# the internal development record: bounded, because this text reaches a job error and the
# operator's browser. Enough to carry a traceback, not enough to carry a log file.
STARTUP_FAILURE_LOG_LINES = 40
STARTUP_FAILURE_LOG_BYTES = 4096
# the internal development record: how long an install watches a freshly started container
# before calling it healthy when it declares no health check, and how recent a
# restart must be for a running container to read RESTARTING rather than RUNNING.
STARTUP_SETTLE_SECONDS = 5
# the internal development record: the same name zfs.py's OPAQUE_PROPERTY carries; spelled
# here so this plugin does not import libzfs through the zfs plugin.
OPAQUE_PROPERTY = 'org.freecore:opaque'
RESTART_WINDOW_SECONDS = 600
# s6-overlay (every Daemonless image) supervises the service inside the container;
# a service that dies is restarted there and podman never sees it.
S6_CRASH_LINE = re.compile(r"\[s6\] Service '([^']+)' crashed")
MAX_MANAGED_CONFIG_SIZE = 1024 * 1024
PF_BLOCK_FILE = '/etc/pf.conf.block'
JAIL_BRIDGE = 'bridge0'
# the bridge podman's CNI plugin creates for the managed network on first use
CNI_BRIDGE = 'cni-podman0'
PODMAN_NETWORK_OPERATIONS = {'create', 'restart', 'start'}
RUNTIME_SYSCTLS = {
    'filter_local_original': 'net.pf.filter_local',
    'ipv4_forwarding_original': 'net.inet.ip.forwarding',
    'bridge_pfil_member_original': 'net.link.bridge.pfil_member',
}
async def _generate_pf_checked(middleware):
    # EtcService.generate intentionally logs renderer failures and continues.
    # PF readiness is transactional, so execute this renderer on its worker
    # thread directly and let validation/load/rollback errors reach the caller.
    await middleware.run_in_thread(pf_renderer.render, None, middleware)


class ApplicationsModel(sa.Model):
    __tablename__ = 'services_applications'

    id = sa.Column(sa.Integer(), primary_key=True)
    app_pool = sa.Column(sa.String(120), nullable=True)
    app_subnet = sa.Column(sa.String(43), default=DEFAULT_SUBNET)
    app_restart_on_boot = sa.Column(sa.Boolean(), default=False)
    app_pf_owned = sa.Column(sa.Boolean(), default=False)
    app_filter_local_original = sa.Column(sa.Integer(), nullable=True)
    app_ipv4_forwarding_original = sa.Column(sa.Integer(), nullable=True)
    app_bridge_pfil_member_original = sa.Column(sa.Integer(), nullable=True)
    # the internal development record: both experimental lanes are off by default. With
    # both false a default install renders identical rc.conf and loads no module.
    app_linux_compat_enabled = sa.Column(sa.Boolean(), default=False)
    app_convert_enabled = sa.Column(sa.Boolean(), default=False)


# the internal development record: the settings of an appliance where Applications was
# never configured. unconfigure and a cascading pool deletion return to exactly
# this row, so a later configure starts the same way a fresh install does.
UNCONFIGURED_SETTINGS = {
    'pool': None,
    'subnet': DEFAULT_SUBNET,
    'restart_on_boot': False,
    'pf_owned': False,
    'filter_local_original': None,
    'ipv4_forwarding_original': None,
    'bridge_pfil_member_original': None,
    'linux_compat_enabled': False,
    'convert_enabled': False,
}


def runtime_options(runtime):
    """the internal development record #535: canonical runtime options -- set values only, extra_hosts
    name-sorted with normalised addresses; a repeated or invalid entry raises CallError."""
    runtime = runtime or {}
    if not isinstance(runtime, dict):
        raise CallError('Runtime options must be a mapping.')
    result = {}
    if runtime.get('stop_timeout') is not None:
        result['stop_timeout'] = runtime['stop_timeout']
    extra_hosts = runtime.get('extra_hosts')
    if extra_hosts:
        if not isinstance(extra_hosts, list) or not all(
            isinstance(item, dict) and set(item) == {'host', 'address'} for item in extra_hosts
        ):
            raise CallError('Runtime extra_hosts must be a list of host and address.')
        hosts = [item['host'] for item in extra_hosts]
        if len(set(hosts)) != len(hosts):
            raise CallError('Runtime extra_hosts names must be unique.')
        try:
            result['extra_hosts'] = compose_extra_hosts({item['host']: item['address'] for item in extra_hosts})
        except (ValueError, TypeError) as error:
            raise CallError(f'Runtime {error}.') from None
    return result


class ApplicationsService(Service):

    class Config:
        namespace = 'applications'

    def _pool_transition(self):
        return getattr(self, '_export_state', None)

    def _require_pool_available(self):
        if self._pool_transition() is not None:
            raise CallError('Applications storage is changing or recovering. Retry after the pool operation finishes.')

    @staticmethod
    async def _complete_ignoring_cancellation(awaitable):
        task = asyncio.ensure_future(awaitable)
        while True:
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                if task.done():
                    return task.result()
                # A job may be aborted more than once. Cleanup and destructive
                # mutations must settle before their lifecycle lock is released.
                continue

    @classmethod
    async def _settle_before_reraise(cls, awaitable):
        task = asyncio.ensure_future(awaitable)
        try:
            return await asyncio.shield(task)
        except BaseException:
            with contextlib.suppress(BaseException):
                await cls._complete_ignoring_cancellation(task)
            raise

    async def _reserve_jail_bridge(self):
        # iocage requires the literal bridge0 name. Reserve it before Podman can
        # allocate and rename bridge clone unit 0 for its CNI network.
        await self._settle_before_reraise(
            self.middleware.call('interface.reserve_jail_bridge', JAIL_BRIDGE)
        )

    @accepts()
    async def config(self):
        config = await self.middleware.call(
            'datastore.config', 'services.applications', {'prefix': 'app_'}
        )
        config['configured'] = bool(config['pool'])
        config['runtime_ready'] = bool(config['pool'] and os.path.exists(RUNTIME_READY) and not self._pool_transition())
        config['paths'] = application_paths(config['pool']) if config['pool'] else None
        config['linux_compat'] = await self.linux_compat_status(config['linux_compat_enabled'])
        return config

    @private
    async def linux_compat_status(self, enabled=False):
        """Whether the Linux ABI is loaded right now, whatever the flag says.

        the internal development record: the sysctl node only exists while the module is
        loaded, so one read answers both questions. A tunable or a hand kldload
        shows up as loaded with the flag off, which is exactly the state the
        administrator should be shown.
        """
        try:
            osrelease = await self._sysctl(LINUX_OSRELEASE_SYSCTL)
        except CallError:
            osrelease = None
        # compat.linux.osrelease is served by linux_common.ko, which loads even
        # when linux64.ko cannot (seen on 15.1-RC2: "depends on mqueuefs - not
        # available"). Only the ELF brand module proves a Linux binary can run.
        cp = await run(['kldstat', '-q', '-m', LINUX_ELF_MODULE], check=False, encoding='utf8')
        return {
            'enabled': bool(enabled),
            'loaded': cp.returncode == 0,
            'osrelease': osrelease or None,
        }

    async def _active_controller(self):
        return await self.middleware.call('failover.status') in {'MASTER', 'SINGLE'}

    async def _pf_enabled(self):
        if not os.path.exists('/dev/pf'):
            return False
        cp = await run(['/sbin/pfctl', '-s', 'info'], check=False, encoding='utf8')
        if cp.returncode:
            raise CallError(f'Unable to inspect PF state: {cp.stderr.strip()}')
        return any(line.startswith('Status: Enabled') for line in cp.stdout.splitlines())

    @staticmethod
    def _jail_address_networks(jail):
        networks = []
        for field in ('ip4_addr', 'ip6_addr'):
            for value in str(jail.get(field) or '').split(','):
                value = value.strip()
                if '|' in value:
                    value = value.rsplit('|', 1)[1]
                if not value or value.lower() in {'none', 'dhcp', 'accept_rtadv'}:
                    continue
                try:
                    networks.append(ipaddress.ip_interface(value).network)
                except ValueError:
                    continue

        if jail.get('nat'):
            prefix = str(jail.get('nat_prefix') or '').strip()
            try:
                if '/' not in prefix and prefix.count('.') < 3:
                    octets = prefix.split('.')
                    prefix = '.'.join([*octets, *(['0'] * (4 - len(octets)))])
                    prefix = f'{prefix}/{len(octets) * 8}'
                networks.append(ipaddress.ip_network(prefix, strict=False))
            except ValueError:
                pass
        return networks

    async def _defined_jail_networks(self):
        networks = []
        methods = ['bastille.query']
        if await self.middleware.call('jail.get_activated_pool') is not None:
            methods.insert(0, 'jail.query')
        for method in methods:
            jails = await self.middleware.call(method)
            networks.extend(
                network
                for jail in jails
                for network in self._jail_address_networks(jail)
            )
        return networks

    async def _validate_pool_and_subnet(
        self, pool_name, subnet, *, allow_managed_store=False, replacing_subnet=None,
        allow_managed_pf=False,
    ):
        verrors = ValidationErrors()
        if not await self._active_controller():
            verrors.add(
                'applications_configure.pool',
                'Applications can only be configured on the active controller.',
            )

        pools = await self.middleware.call('pool.query', [('name', '=', pool_name)])
        if not pools:
            verrors.add('applications_configure.pool', f'Pool {pool_name!r} is not imported.')
        else:
            pool = pools[0]
            if pool_name == await self.middleware.call('boot.pool_name'):
                verrors.add('applications_configure.pool', 'Applications cannot use the boot pool.')
            if pool['status'] != 'ONLINE' or not pool['healthy'] or not pool['is_decrypted']:
                verrors.add(
                    'applications_configure.pool',
                    'Applications require a healthy, online, unlocked data pool.',
                )

        paths = application_paths(pool_name)
        store_exists = await self._dataset_exists(paths['dataset'])
        if store_exists:
            if allow_managed_store:
                try:
                    await self._validate_application_store(pool_name)
                except CallError as error:
                    verrors.add('applications_configure.pool', error.errmsg)
            else:
                verrors.add(
                    'applications_configure.pool',
                    f'{paths["dataset"]!r} already exists and is not owned by Applications.',
                )

        requested = ipaddress.ip_network(subnet, strict=True)
        replacing = (
            ipaddress.ip_network(replacing_subnet, strict=True)
            if replacing_subnet else None
        )
        collisions = []
        for route in await self.middleware.call('route.system_routes'):
            try:
                network = ipaddress.ip_network(
                    f'{route["network"]}/{route["netmask"]}', strict=False
                )
            except (KeyError, ValueError):
                continue
            if network.version != requested.version or network.prefixlen == 0:
                continue
            # The currently selected Podman network is removed from service by this
            # transaction. Do not report its own route as a collision when retaining
            # the subnet while selecting another Applications store.
            if replacing is not None and network == replacing:
                continue
            if requested.overlaps(network):
                collisions.append(str(network))

        for network in await self._defined_jail_networks():
            if network.version == requested.version and requested.overlaps(network):
                collisions.append(f'{network} (defined jail)')

        if collisions:
            verrors.add(
                'applications_configure.subnet',
                f'Container subnet overlaps existing network(s): {", ".join(sorted(set(collisions)))}.',
            )

        if not os.access(PODMAN_PATH, os.X_OK):
            verrors.add(
                'applications_configure.pool',
                f'Podman runtime is not installed at {PODMAN_PATH}.',
            )

        failover_licensed = await self.middleware.call('failover.licensed')
        if not allow_managed_pf and not failover_licensed and (
            await self._pf_enabled() or os.path.exists(PF_BLOCK_FILE)
        ):
            verrors.add(
                'applications_configure.subnet',
                'PF is already active or has an unmanaged ruleset; Applications will not replace it.',
            )

        verrors.check()
        return store_exists

    @staticmethod
    def _application_dataset_specs(pool_name):
        paths = application_paths(pool_name)
        return [
            (paths['dataset'], 'applications'),
            (paths['storage_dataset'], 'applications:storage'),
            (paths['config_dataset'], 'applications:config'),
            (paths['records_dataset'], 'applications:records'),
            (paths['data_dataset'], 'applications:data'),
        ]

    async def _validate_application_store(self, pool_name):
        for dataset, owner in self._application_dataset_specs(pool_name):
            if not await self._dataset_exists(dataset):
                raise CallError(f'Applications dataset {dataset!r} is unavailable.')
            if await self._dataset_owner(dataset) != owner:
                raise CallError(
                    f'Applications dataset {dataset!r} does not have valid local ownership.'
                )
            mountpoint = f'/mnt/{dataset}'
            if not os.path.ismount(mountpoint):
                raise CallError(
                    f'Applications dataset {dataset!r} is not mounted at {mountpoint!r}.'
                )

    async def _create_application_datasets(self, pool_name, created):
        for dataset, owner in self._application_dataset_specs(pool_name):
            # Record the attempted dataset before the cancellable create call. A
            # successful create whose response is interrupted must still be owned
            # by rollback.
            created.append(dataset)
            await self._settle_before_reraise(self.middleware.call(
                'zfs.dataset.create', {
                    'name': dataset,
                    'properties': {
                        'atime': 'off',
                        'compression': 'lz4',
                        MANAGED_PROPERTY: owner,
                    },
                }
            ))
            await self._settle_before_reraise(
                self.middleware.call('zfs.dataset.mount', dataset)
            )

    async def _recover_storage_mountpoints(self, config):
        await self._validate_application_store(config['pool'])
        paths = application_paths(config['pool'])
        ids = await self.middleware.run_in_thread(read_layer_ids, paths['storage'])
        plan = await layer_recovery_plan(paths, ids)
        if not plan:
            return
        self._validate_managed_configs(config['pool'])
        running = await self._podman(config, 'ps', '--quiet')
        if running.stdout.strip():
            raise CallError('Stop all containers in the Applications store before recovering its layer mounts.')
        jails = await run(['jls', '-n', 'path'], check=False, encoding='utf8')
        if jails.returncode:
            raise CallError('Unable to check active jails before recovering Applications storage.')
        try:
            jail_paths = [dict(item.split('=', 1) for item in shlex.split(line))['path']
                          for line in jails.stdout.splitlines()]
        except (KeyError, ValueError) as error:
            raise CallError('Unable to interpret active jail paths.') from error
        if any(path == paths['storage'] or path.startswith(paths['storage'] + '/') for path in jail_paths):
            raise CallError('Stop jails using Applications storage before recovering its layer mounts.')
        await self._settle_before_reraise(restore_layer_mountpoints(plan))

    async def _delete_attempted_owned_datasets(self, created, owners):
        errors = []
        for dataset in reversed(created):
            try:
                if not await self._dataset_exists(dataset):
                    continue
                expected_owner = owners[dataset]
                actual_owner = await self._dataset_owner(dataset)
                if actual_owner != expected_owner:
                    errors.append(
                        f'refused to remove {dataset!r}: expected ownership '
                        f'{expected_owner!r}, found {actual_owner!r}'
                    )
                    continue
                # Delete only the exact dataset. Reversed creation order removes
                # owned children first, while an unexpected descendant makes ZFS
                # refuse the parent instead of broadening deletion.
                await self.middleware.call(
                    'zfs.dataset.delete', dataset, {'force': True, 'recursive': False}
                )
            except Exception as error:  # noqa: BLE001
                errors.append(f'remove attempted dataset {dataset!r}: {error}')
        return errors

    @staticmethod
    def _clear_runtime_state():
        for path in (RUNTIME_READY, RUNTIME_PF_ACTIVE):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)

    @staticmethod
    def _mark_pf_active():
        atomic_write(RUNTIME_PF_ACTIVE, 'active\n')

    @staticmethod
    def _mark_runtime_ready():
        atomic_write(RUNTIME_READY, 'ready\n')

    def _write_managed_configs(self, pool_name, subnet):
        paths = application_paths(pool_name)
        os.makedirs(paths['cni'], mode=0o755, exist_ok=True)
        atomic_write(paths['storage_conf'], render_storage_conf(pool_name))
        atomic_write(paths['containers_conf'], render_containers_conf(pool_name, subnet))

    @staticmethod
    def _snapshot_managed_configs(pool_name):
        paths = application_paths(pool_name)
        snapshot = {}
        for path in (paths['storage_conf'], paths['containers_conf']):
            try:
                metadata = os.lstat(path)
            except FileNotFoundError:
                snapshot[path] = None
                continue
            except OSError as error:
                raise CallError(f'Unable to inspect Applications configuration {path!r}: {error}')
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_MANAGED_CONFIG_SIZE:
                raise CallError(f'Applications configuration {path!r} is unsafe or too large.')
            try:
                snapshot[path] = Path(path).read_text(encoding='utf8')
            except (OSError, UnicodeDecodeError) as error:
                raise CallError(f'Unable to read Applications configuration {path!r}: {error}')
        return snapshot

    @staticmethod
    def _restore_managed_configs(snapshot):
        for path, content in snapshot.items():
            if content is None:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path)
            else:
                atomic_write(path, content)

    def _validate_managed_configs(self, pool_name, expected_subnet=None):
        paths = application_paths(pool_name)
        snapshot = self._snapshot_managed_configs(pool_name)
        if snapshot[paths['storage_conf']] != render_storage_conf(pool_name):
            raise CallError(
                f'Applications storage configuration for pool {pool_name!r} is missing or unsafe.'
            )

        containers = snapshot[paths['containers_conf']]
        if containers is None:
            raise CallError(
                f'Applications network configuration for pool {pool_name!r} is missing.'
            )
        subnet_lines = [
            line.partition('=')[2].strip()
            for line in containers.splitlines()
            if line.startswith('default_subnet =')
        ]
        try:
            subnet = json.loads(subnet_lines[0]) if len(subnet_lines) == 1 else None
            network = ipaddress.ip_network(subnet, strict=True)
        except (TypeError, ValueError, json.JSONDecodeError):
            network = None
        if (
            network is None or
            network.version != 4 or
            str(network) != subnet or
            containers != render_containers_conf(pool_name, subnet)
        ):
            raise CallError(
                f'Applications network configuration for pool {pool_name!r} is unsafe.'
            )
        if expected_subnet is not None and subnet != expected_subnet:
            raise CallError(
                f'Applications network configuration for pool {pool_name!r} does not match '
                'the selected managed subnet.'
            )
        return snapshot

    async def _sysctl(self, name):
        cp = await run(['sysctl', '-n', name], check=False, encoding='utf8')
        if cp.returncode:
            raise CallError(f'Unable to read {name}: {cp.stderr.strip()}')
        return cp.stdout.strip()

    async def _set_sysctl(self, name, value):
        cp = await run(['sysctl', f'{name}={value}'], check=False, encoding='utf8')
        if cp.returncode:
            raise CallError(f'Unable to set {name}: {cp.stderr.strip()}')

    async def _capture_runtime_sysctls(self):
        originals = {}
        for field, name in RUNTIME_SYSCTLS.items():
            value = await self._sysctl(name)
            if value not in {'0', '1'}:
                raise CallError(f'Unexpected {name} value: {value!r}')
            originals[field] = int(value)
        return originals

    async def _apply_runtime_sysctls(self):
        for name in RUNTIME_SYSCTLS.values():
            await self._set_sysctl(name, '1')

    async def _restore_runtime_sysctls(self, config):
        errors = []
        for field, name in RUNTIME_SYSCTLS.items():
            value = config.get(field)
            if value is None:
                continue
            try:
                await self._set_sysctl(name, str(value))
            except Exception as error:
                errors.append(f'restore {name}: {error}')
                self.logger.warning(
                    'Failed to restore %s during Applications runtime cleanup', name, exc_info=True
                )
        return errors

    async def _ensure_pf_module(self):
        if os.path.exists('/dev/pf'):
            return
        cp = await run(['kldload', 'pf'], check=False, encoding='utf8')
        if cp.returncode and not os.path.exists('/dev/pf'):
            raise CallError(f'Unable to load PF: {cp.stderr.strip()}')

    async def _disable_owned_pf(self, config):
        if not config.get('pf_owned') or await self.middleware.call('failover.licensed'):
            return
        if not await self._pf_enabled():
            return
        cp = await run(['/sbin/pfctl', '-d'], check=False, encoding='utf8')
        if cp.returncode:
            raise CallError(f'Unable to disable Applications-owned PF: {cp.stderr.strip()}')
        cp = await run(['/sbin/pfctl', '-F', 'all'], check=False, encoding='utf8')
        if cp.returncode:
            raise CallError(f'Unable to flush Applications-owned PF state: {cp.stderr.strip()}')

    async def _rollback_initial_configure(
        self, old, pool, original_sysctls, pf_owned, created, datastore_update_attempted,
        config_snapshot=None,
    ):
        errors = []
        try:
            self._clear_runtime_state()
        except Exception as error:  # noqa: BLE001
            errors.append(f'clear runtime markers: {error}')
        if datastore_update_attempted:
            try:
                await self.middleware.call(
                    'datastore.update', 'services.applications', old['id'], {
                        'pool': old['pool'],
                        'subnet': old['subnet'],
                        'restart_on_boot': old['restart_on_boot'],
                        'pf_owned': old['pf_owned'],
                        'filter_local_original': old['filter_local_original'],
                        'ipv4_forwarding_original': old['ipv4_forwarding_original'],
                        'bridge_pfil_member_original': old['bridge_pfil_member_original'],
                    }, {'prefix': 'app_'}
                )
            except Exception as error:  # noqa: BLE001
                errors.append(f'database restore: {error}')
        try:
            errors.extend(await self._restore_runtime_sysctls(original_sysctls))
        except Exception as error:  # noqa: BLE001
            errors.append(f'runtime sysctl restore: {error}')
        if created:
            owners = dict(self._application_dataset_specs(pool))
            errors.extend(await self._delete_attempted_owned_datasets(created, owners))
        elif config_snapshot is not None:
            try:
                self._restore_managed_configs(config_snapshot)
            except Exception as error:  # noqa: BLE001
                errors.append(f'Applications configuration restore: {error}')
        try:
            await self.middleware.call('etc.generate', 'rc')
        except Exception as error:  # noqa: BLE001
            errors.append(f'rc regeneration: {error}')
        try:
            await _generate_pf_checked(self.middleware)
        except Exception as error:  # noqa: BLE001
            errors.append(f'PF regeneration: {error}')
        try:
            await self._disable_owned_pf({'pf_owned': pf_owned})
        except Exception as error:  # noqa: BLE001
            errors.append(f'Applications-owned PF cleanup: {error}')
        return errors

    @lock('applications_lifecycle_internal')
    @accepts(Dict(
        'applications_configure',
        Str('pool', required=True, empty=False),
        IPAddr('subnet', network=True, network_strict=True, v4=True, v6=False, default=DEFAULT_SUBNET),
        Bool('linux_compat_enabled', default=False),
        Bool('convert_enabled', default=False),
    ))
    @job(lock='applications_lifecycle')
    async def configure(self, job, data):
        self._require_pool_available()
        old = await self.config()
        if old['pool']:
            if old['pool'] == data['pool'] and old['subnet'] == data['subnet']:
                await self._runtime_setup_impl()
                await self._apply_experimental_flags(job, old, data)
                return await self.config()
            await self._apply_experimental_flags(job, old, data)
            return await self._reconfigure(job, old, data)

        store_exists = await self._validate_pool_and_subnet(
            data['pool'], data['subnet'], allow_managed_store=True,
        )
        config_snapshot = None
        restart_on_boot = False
        if store_exists:
            # A fresh appliance configuration can explicitly select its prior
            # owned store. Keep its network settings, records and data intact.
            self._validate_managed_configs(data['pool'], data['subnet'])
            target = {**old, **data, 'runtime_ready': False}
            running = await self._running_managed(target, strict=True)
            if running:
                raise CallError(
                    'Stop all Applications before selecting their existing store: '
                    f'{", ".join(running)}.'
                )
            records, errors = self._read_records(target)
            if errors:
                raise CallError('The existing Applications store contains invalid managed records.')
            restart_on_boot = any(record.get('restart_policy') == 'always' for record in records)
            config_snapshot = self._snapshot_managed_configs(data['pool'])
            await self._recover_storage_mountpoints(target)
        await self._ensure_pf_module()
        original_sysctls = await self._capture_runtime_sysctls()
        pf_enabled = await self._pf_enabled()
        pf_owned = not pf_enabled
        created = []
        datastore_update_attempted = False

        try:
            job.set_progress(10, 'Selecting Applications datasets')
            if not store_exists:
                await self._create_application_datasets(data['pool'], created)
            self._write_managed_configs(data['pool'], data['subnet'])
            os.makedirs(VOLATILE_RUNROOT, mode=0o700, exist_ok=True)

            datastore_update_attempted = True
            await self._settle_before_reraise(self.middleware.call(
                'datastore.update', 'services.applications', old['id'], {
                    'pool': data['pool'],
                    'subnet': data['subnet'],
                    'restart_on_boot': restart_on_boot,
                    'pf_owned': pf_owned,
                    **original_sysctls,
                }, {'prefix': 'app_'}
            ))

            job.set_progress(60, 'Applying Applications runtime prerequisites')
            await self._reserve_jail_bridge()
            await self._settle_before_reraise(self._apply_runtime_sysctls())
            self._mark_pf_active()
            await self._settle_before_reraise(_generate_pf_checked(self.middleware))
            self._mark_runtime_ready()
            await self._settle_before_reraise(
                self.middleware.call('etc.generate', 'rc')
            )
        except BaseException as error:
            rollback_errors = await self._complete_ignoring_cancellation(
                self._rollback_initial_configure(
                    old, data['pool'], original_sysctls, pf_owned, created,
                    datastore_update_attempted, config_snapshot,
                )
            )
            if rollback_errors:
                message = getattr(error, 'errmsg', str(error)) or type(error).__name__
                raise CallError(
                    f'{message} Applications configuration rollback was incomplete: '
                    f'{"; ".join(rollback_errors)}'
                ) from error
            raise

        await self._apply_experimental_flags(job, old, data)
        job.set_progress(100, 'Applications is ready')
        return await self._complete_ignoring_cancellation(self.config())

    async def _apply_experimental_flags(self, job, current, data):
        """the internal development record/#444: the two opt-in lanes, applied beside the pool.

        The Linux ABI flag is the only one with a system side effect. It owns the
        rc.conf lines and runs the base rc script (which loads the modules *and*
        sets the ELF fallback brand), then proves the module is loaded before the
        setting is kept. Disabling refuses while a Linux application exists and
        leaves the modules loaded until reboot: unloading with jails alive is not
        something the product attempts.
        """
        updates = {}
        want_convert = bool(data.get('convert_enabled', False))
        if want_convert != bool(current.get('convert_enabled', False)):
            updates['convert_enabled'] = want_convert
        want_linux = bool(data.get('linux_compat_enabled', False))
        previous_linux = bool(current.get('linux_compat_enabled', False))
        if want_linux != previous_linux:
            if not want_linux:
                records, _ = self._read_records(current)
                linux_records = sorted(
                    record['name'] for record in records if record.get('image_os') == 'linux'
                )
                if linux_records:
                    raise CallError(
                        'Remove the Linux applications before disabling Linux binary '
                        f'compatibility: {", ".join(linux_records)}.'
                    )
            updates['linux_compat_enabled'] = want_linux
        if not updates:
            return
        await self._settle_before_reraise(self.middleware.call(
            'datastore.update', 'services.applications', current['id'], updates, {'prefix': 'app_'}
        ))
        if 'linux_compat_enabled' not in updates:
            return
        try:
            await self._settle_before_reraise(self.middleware.call('etc.generate', 'rc'))
            if want_linux:
                job.set_progress(90, 'Enabling Linux binary compatibility')
                cp = await run(['service', LINUX_RC_SCRIPT, 'start'], check=False, encoding='utf8')
                if cp.returncode:
                    detail = (cp.stderr or cp.stdout or '').strip()[-1024:]
                    raise CallError(f'Unable to start the Linux ABI service: {detail}')
                status = await self.linux_compat_status(True)
                if not status['loaded']:
                    dmesg = await run(['dmesg'], check=False, encoding='utf8')
                    detail = '; '.join(
                        line.strip() for line in (dmesg.stdout or '').splitlines()
                        if 'linux' in line.lower() and ('depends on' in line or 'unsupported' in line)
                    )[-512:]
                    raise CallError(
                        'The Linux ABI service started but the 64-bit Linux ELF module '
                        f'({LINUX_ELF_MODULE}) is not loaded, so no Linux binary can run'
                        + (f': {detail}' if detail else '.')
                    )
            else:
                job.set_progress(
                    90, 'Linux binary compatibility disabled; loaded modules remain until reboot'
                )
        except BaseException:
            with contextlib.suppress(Exception):
                await self.middleware.call(
                    'datastore.update', 'services.applications', current['id'],
                    {'linux_compat_enabled': previous_linux}, {'prefix': 'app_'},
                )
            with contextlib.suppress(Exception):
                await self.middleware.call('etc.generate', 'rc')
            raise

    async def _reconfigure(self, job, old, data):
        switching_pool = old['pool'] != data['pool']
        await self._validate_pool_and_subnet(
            data['pool'], data['subnet'],
            allow_managed_store=True,
            replacing_subnet=old['subnet'],
            allow_managed_pf=True,
        )

        if switching_pool and not old['runtime_ready']:
            # A restart while the old pool is absent loses the in-memory gate.
            # Do not abandon external references in an unavailable record store.
            await self._validate_application_store(old['pool'])
        current_records = self._attachment_records(old)
        if data['subnet'] != old['subnet']:
            # the internal development record: pinned bridge addresses live in the current
            # subnet and are part of each container's configuration.
            pinned = sorted(record['name'] for record in current_records if self._bridge_pins(record))
            if pinned:
                raise CallError(
                    'These applications keep a fixed address on the managed bridge and would '
                    f'lose their network if the subnet changed: {", ".join(pinned)}. Remove them '
                    '(their data is kept), change the subnet, then install them again.'
                )
        if switching_pool and any(not volume['owned'] for record in current_records for volume in record['volumes']):
            raise CallError('Remove Applications with external dataset references before changing the data pool.')
        if current_records:
            self._validate_managed_configs(old['pool'], old['subnet'])
        running = await self._running_managed(old, strict=True)
        if running:
            raise CallError(
                'Stop all Applications before changing the data pool or managed subnet: '
                f'{", ".join(running)}.'
            )

        target_exists = await self._dataset_exists(application_paths(data['pool'])['dataset'])
        target = {**old, 'pool': data['pool'], 'subnet': data['subnet'], 'runtime_ready': False}
        if switching_pool and target_exists:
            target_records, _ = self._read_records(target)
            if target_records:
                self._validate_managed_configs(data['pool'])
            target_running = await self._running_managed(target, strict=True)
            if target_running:
                raise CallError(
                    f'Stop all Applications in target pool {data["pool"]!r} before selecting it: '
                    f'{", ".join(target_running)}.'
                )

        created = []
        snapshot = None
        datastore_update_attempted = False
        transition_started = False
        try:
            job.set_progress(10, 'Selecting the Applications dataset hierarchy')
            if target_exists:
                snapshot = self._snapshot_managed_configs(data['pool'])
            else:
                await self._create_application_datasets(data['pool'], created)

            # Keep the old store intact, but remove it from runtime service before
            # changing the database pointer or Podman network configuration.
            transition_started = True
            self._clear_runtime_state()
            await self._settle_before_reraise(
                self.middleware.call('etc.generate', 'rc')
            )
            await self._settle_before_reraise(_generate_pf_checked(self.middleware))

            job.set_progress(45, 'Writing Applications storage and network settings')
            self._write_managed_configs(data['pool'], data['subnet'])
            datastore_update_attempted = True
            await self._settle_before_reraise(self.middleware.call(
                'datastore.update', 'services.applications', old['id'], {
                    'pool': data['pool'],
                    'subnet': data['subnet'],
                }, {'prefix': 'app_'}
            ))

            job.set_progress(70, 'Applying Applications runtime prerequisites')
            await self._runtime_setup_impl()
        except BaseException as error:
            if not transition_started and not created:
                raise

            rollback_errors = await self._complete_ignoring_cancellation(
                self._rollback_reconfigure(
                    old, data['pool'], created, snapshot, datastore_update_attempted,
                )
            )

            if rollback_errors:
                with contextlib.suppress(Exception):
                    await self._restore_runtime_sysctls(old)
                with contextlib.suppress(Exception):
                    await self._disable_owned_pf(old)
                message = getattr(error, 'errmsg', str(error)) or type(error).__name__
                raise CallError(
                    f'{message} Applications settings rollback was incomplete: '
                    f'{"; ".join(rollback_errors)}'
                ) from error
            raise

        job.set_progress(100, 'Applications storage and network settings are ready')
        return await self._complete_ignoring_cancellation(self.config())

    async def _rollback_reconfigure(
        self, old, target_pool, created, snapshot, datastore_update_attempted,
    ):
        rollback_errors = []
        try:
            self._clear_runtime_state()
        except Exception as rollback_error:  # noqa: BLE001
            rollback_errors.append(f'clear runtime markers failed: {rollback_error}')
        if datastore_update_attempted:
            try:
                await self.middleware.call(
                    'datastore.update', 'services.applications', old['id'], {
                        'pool': old['pool'],
                        'subnet': old['subnet'],
                        'restart_on_boot': old['restart_on_boot'],
                    }, {'prefix': 'app_'}
                )
            except Exception as rollback_error:  # noqa: BLE001
                rollback_errors.append(f'database restore failed: {rollback_error}')

        try:
            if created:
                rollback_errors.extend(await self._delete_attempted_owned_datasets(
                    created, dict(self._application_dataset_specs(target_pool))
                ))
            elif snapshot is not None:
                self._restore_managed_configs(snapshot)
        except Exception as rollback_error:  # noqa: BLE001
            rollback_errors.append(f'target-store restore failed: {rollback_error}')

        try:
            if old['runtime_ready']:
                await self._runtime_setup_impl()
            else:
                await self.middleware.call('etc.generate', 'rc')
                await _generate_pf_checked(self.middleware)
        except Exception as rollback_error:  # noqa: BLE001
            rollback_errors.append(f'runtime restore failed: {rollback_error}')
        return rollback_errors

    @lock('applications_lifecycle_internal')
    @accepts(Dict(
        'applications_unconfigure',
        Bool('remove_applications', default=False),
        Bool('keep_data', default=False),
        default={},
    ))
    @job(lock='applications_lifecycle')
    async def unconfigure(self, job, options):
        """Return the appliance to the state where Applications was never configured.

        the internal development record: this is the explicit removal the pool attachment
        refusal asks for. Installed applications are refused unless
        `remove_applications` is set; then each is removed exactly as
        `applications.remove` would, with its data unless `keep_data`. The runtime is
        taken down (workloads, PF ownership, sysctls, rc.conf lines), the settings
        return to their defaults, and the store's datasets are destroyed — or, with
        `keep_data`, left on the pool, where `applications.configure` of that pool
        selects them again.
        """
        self._require_pool_available()
        config = await self.config()
        if not config['pool']:
            return config
        pool = config['pool']
        await self._validate_application_store(pool)
        records, errors = self._read_records(config)
        if errors:
            raise CallError(
                'Applications storage contains invalid managed records; unconfiguring is unsafe.'
            )
        if records and not options['remove_applications']:
            raise CallError(
                'Remove the installed applications first, or unconfigure with '
                f'remove_applications: {", ".join(sorted(record["name"] for record in records))}.'
            )
        if records and not config['runtime_ready']:
            raise CallError(
                'The Applications runtime is not ready, so its applications cannot be removed. '
                'Configure the same pool again to restore the runtime, then retry.'
            )

        paths = application_paths(pool)
        for index, record in enumerate(sorted(records, key=lambda record: record['name'])):
            job.set_progress(
                10 + 40 * index // len(records), f'Removing application {record["name"]!r}'
            )
            app_dataset = f'{paths["data_dataset"]}/{record["name"]}'
            owner = f'applications:{record["name"]}'
            remove_dataset = not options['keep_data'] and await self._dataset_exists(app_dataset)
            if remove_dataset:
                await self._owned_tree(app_dataset, owner)
            # each removal is its own retryable transaction, like applications.remove
            await self._complete_ignoring_cancellation(
                self._remove_impl(config, record, app_dataset, remove_dataset)
            )

        job.set_progress(50, 'Stopping the Applications runtime')
        # fail-closed: an incomplete teardown leaves the pool selected and raises
        await self._complete_ignoring_cancellation(self._runtime_teardown_impl(config))
        await self._complete_ignoring_cancellation(self._remove_runtime_bridge())

        job.set_progress(70, 'Forgetting the Applications settings')
        await self._forget_settings(config)

        if not options['keep_data']:
            job.set_progress(80, 'Removing orphaned application data')
            leftovers = await self._complete_ignoring_cancellation(
                self._remove_orphaned_application_data(paths)
            )
            job.set_progress(85, 'Destroying the Applications store')
            leftovers += await self._complete_ignoring_cancellation(self._destroy_store(pool))
            if leftovers:
                raise CallError(
                    'Applications is unconfigured, but its store was not fully removed: '
                    f'{"; ".join(leftovers)}'
                )
        job.set_progress(100, 'Applications is unconfigured')
        return await self._complete_ignoring_cancellation(self.config())

    async def _remove_runtime_bridge(self):
        """The CNI bridge outlives the containers it served. With the runtime down it
        has no purpose, and its connected route would make the next configure report
        the managed subnet as taken by an existing network. Only an empty bridge goes;
        a member interface means something still runs on it, and that is refused."""
        cp = await run(['ifconfig', CNI_BRIDGE], check=False, encoding='utf8')
        if cp.returncode:
            return False
        if 'member:' in cp.stdout:
            raise CallError(f'The container bridge {CNI_BRIDGE} still has member interfaces.')
        cp = await run(['ifconfig', CNI_BRIDGE, 'destroy'], check=False, encoding='utf8')
        if cp.returncode:
            raise CallError(
                f'Unable to remove the container bridge {CNI_BRIDGE}: {cp.stderr.strip()}'
            )
        return True

    async def _forget_settings(self, config):
        """Write the never-configured row and render the rc/PF state that follows from it."""
        await self._settle_before_reraise(self.middleware.call(
            'datastore.update', 'services.applications', config['id'],
            dict(UNCONFIGURED_SETTINGS), {'prefix': 'app_'},
        ))
        self._export_state = None
        await self._settle_before_reraise(self.middleware.call('etc.generate', 'rc'))
        await self._settle_before_reraise(_generate_pf_checked(self.middleware))

    async def _remove_orphaned_application_data(self, paths):
        """the internal development record: application data nobody maps any more — what an
        earlier keep-data unconfigure or a Remove without its data left under the
        store — is exactly the data a `keep_data: false` unconfigure is asked to
        delete, and the store's parent cannot go while it is there. Each orphan
        parent goes the way an installed application's data goes: the whole tree
        re-verified as owned by that application immediately before deletion,
        then deleted one dataset at a time, children first. A tree with a member
        owned by anything else is refused and reported, and _destroy_store then
        refuses the store's parent as before; deletion is never broadened.
        Returns what could not go."""
        errors = []
        prefix = paths['data_dataset'] + '/'
        rows = await self._list_owned_datasets(paths['data_dataset'])
        parents = sorted({
            dataset for dataset, _, _, _ in rows
            if dataset.startswith(prefix) and '/' not in dataset[len(prefix):]
        })
        for parent in parents:
            owner = f'applications:{parent[len(prefix):]}'
            try:
                datasets = await self._owned_tree(parent, owner)
            except CallError as error:
                errors.append(str(error))
                continue
            errors.extend(await self._delete_attempted_owned_datasets(
                datasets, {dataset: owner for dataset in datasets}
            ))
        return errors

    async def _destroy_store(self, pool):
        """Destroy the owned store datasets, children first. Returns what could not go.

        Podman's ZFS driver keeps one child dataset per image layer under the storage
        dataset; none of them carries our ownership property, they are the store's
        contents and go with it once the parent's ownership has been verified. The
        other datasets are removed one by one, without recursion, so anything
        unexpected inside them makes ZFS refuse the parent instead of broadening the
        deletion.
        """
        errors = []
        specs = self._application_dataset_specs(pool)
        owners = dict(specs)
        storage = application_paths(pool)['storage_dataset']
        try:
            if await self._dataset_exists(storage):
                actual = await self._dataset_owner(storage)
                if actual != owners[storage]:
                    errors.append(
                        f'refused to remove {storage!r}: expected ownership '
                        f'{owners[storage]!r}, found {actual!r}'
                    )
                else:
                    await self.middleware.call(
                        'zfs.dataset.delete', storage, {'force': True, 'recursive': True}
                    )
        except Exception as error:  # noqa: BLE001
            errors.append(f'remove {storage!r}: {error}')
        errors.extend(await self._delete_attempted_owned_datasets(
            [dataset for dataset, _ in specs if dataset != storage], owners,
        ))
        return errors

    @private
    @lock('applications_lifecycle_internal')
    async def deactivate_pool(self, pool):
        """the internal development record: the pool that holds the store is being deleted with
        `cascade`, and that is the explicit removal. Stop what runs, take the runtime
        down and forget the settings; the store's datasets are left to the pool
        operation (a destroy takes them, an export keeps them for a later
        applications.configure of the same pool), exactly as bastille.deactivate_pool
        leaves its jails."""
        config = await self.config()
        if config['pool'] != pool:
            return False
        if self._pool_transition() is not None:
            raise CallError('Applications pool transition is already in progress.')
        await self._complete_ignoring_cancellation(self._runtime_teardown_impl(config))
        await self._complete_ignoring_cancellation(self._remove_runtime_bridge())
        await self._forget_settings(config)
        return True

    @private
    @lock('applications_lifecycle_internal')
    async def runtime_setup(self):
        return await self._runtime_setup_impl()

    async def _runtime_setup_impl(self, *, allow_pool_transition=False):
        if self._pool_transition() is not None and not allow_pool_transition:
            return False
        config = await self.config()
        if not config['pool']:
            self._clear_runtime_state()
            return False

        was_ready = config['runtime_ready']
        active_controller = await self._active_controller()
        if active_controller:
            # A refused repair must not enter rollback that stops healthy apps.
            # Pool import and system-ready hooks run this before boot replay.
            await self._recover_storage_mountpoints(config)
        self._clear_runtime_state()
        if not active_controller:
            return await self._complete_ignoring_cancellation(
                self._deactivate_runtime(config, was_ready)
            )

        paths = application_paths(config['pool'])
        expected = {
            paths['dataset']: 'applications',
            paths['storage_dataset']: 'applications:storage',
            paths['config_dataset']: 'applications:config',
            paths['records_dataset']: 'applications:records',
            paths['data_dataset']: 'applications:data',
        }
        try:
            for dataset, owner in expected.items():
                if not await self._dataset_exists(dataset):
                    raise CallError(f'Applications dataset {dataset!r} is unavailable.')
                if await self._dataset_owner(dataset) != owner:
                    raise CallError(f'Applications dataset {dataset!r} has invalid ownership.')

            await self._reserve_jail_bridge()
            await self._mark_store_opaque(paths['storage_dataset'])
            self._write_managed_configs(config['pool'], config['subnet'])
            os.makedirs(VOLATILE_RUNROOT, mode=0o700, exist_ok=True)
            if not os.access(PODMAN_PATH, os.X_OK):
                raise CallError(f'Podman runtime is not installed at {PODMAN_PATH}.')
            await self._ensure_pf_module()
            await self._settle_before_reraise(self._apply_runtime_sysctls())
            await self._settle_before_reraise(self._refresh_restart_on_boot(config))
            self._mark_pf_active()
            await self._settle_before_reraise(_generate_pf_checked(self.middleware))
            self._mark_runtime_ready()
            await self._settle_before_reraise(
                self.middleware.call('etc.generate', 'rc')
            )
        except BaseException as error:
            rollback_errors = await self._complete_ignoring_cancellation(
                self._rollback_runtime_setup(config, was_ready)
            )
            if rollback_errors:
                message = getattr(error, 'errmsg', str(error)) or type(error).__name__
                raise CallError(
                    f'{message} Applications runtime rollback was incomplete: '
                    f'{"; ".join(rollback_errors)}'
                ) from error
            raise
        return True

    async def _deactivate_runtime(self, config, was_ready):
        errors = []
        if was_ready:
            try:
                failed = await self._stop_managed(config)
                if failed:
                    errors.append(f'workloads not stopped: {", ".join(sorted(failed))}')
            except Exception as error:  # noqa: BLE001
                errors.append(f'stop managed applications: {error}')
        try:
            errors.extend(await self._restore_runtime_sysctls(config))
        except Exception as error:  # noqa: BLE001
            errors.append(f'runtime sysctl restore: {error}')
        try:
            await self.middleware.call('etc.generate', 'rc')
        except Exception as error:  # noqa: BLE001
            errors.append(f'rc regeneration: {error}')
        try:
            await _generate_pf_checked(self.middleware)
        except Exception as error:  # noqa: BLE001
            errors.append(f'PF regeneration: {error}')
        try:
            await self._disable_owned_pf(config)
        except Exception as error:  # noqa: BLE001
            errors.append(f'Applications-owned PF cleanup: {error}')
        if errors:
            raise CallError(
                f'Applications runtime cleanup was incomplete ({"; ".join(errors)}).'
            )
        return False

    async def _rollback_runtime_setup(self, config, was_ready):
        errors = []
        if was_ready:
            try:
                failed = await self._stop_managed(config)
                if failed:
                    errors.append(f'workloads not stopped: {", ".join(sorted(failed))}')
            except Exception as error:  # noqa: BLE001
                errors.append(f'stop managed applications: {error}')
        try:
            self._clear_runtime_state()
        except Exception as error:  # noqa: BLE001
            errors.append(f'clear runtime markers: {error}')
        try:
            errors.extend(await self._restore_runtime_sysctls(config))
        except Exception as error:  # noqa: BLE001
            errors.append(f'runtime sysctl restore: {error}')
        try:
            await self.middleware.call('etc.generate', 'rc')
        except Exception as error:  # noqa: BLE001
            errors.append(f'rc regeneration: {error}')
        try:
            await _generate_pf_checked(self.middleware)
        except Exception as error:  # noqa: BLE001
            errors.append(f'PF regeneration: {error}')
        try:
            await self._disable_owned_pf(config)
        except Exception as error:  # noqa: BLE001
            errors.append(f'Applications-owned PF cleanup: {error}')
        return errors

    async def _require_config(self):
        self._require_pool_available()
        config = await self.config()
        if not config['pool']:
            raise CallError('Applications must be configured on a data pool first.')
        if not config['runtime_ready']:
            raise CallError('Applications runtime prerequisites are not ready on this controller.')
        return config

    @staticmethod
    def _validate_record(
        config, record, expected_name, allow_unbound_container=False,
    ):
        if not isinstance(record, dict):
            raise TypeError('record must be an object')

        name = record.get('name')
        if name != expected_name or not isinstance(name, str) or not re.fullmatch(
            APPLICATION_NAME, name
        ):
            raise ValueError('record name does not match its valid filename')
        schema = record.get('schema')
        if schema not in RECORD_SCHEMAS:
            raise ValueError('unsupported record schema')
        if schema >= 3:
            if record.get('image_os') not in IMAGE_OPERATING_SYSTEMS:
                raise ValueError('record image operating system is invalid')
            origin = record.get('origin')
            if origin is not None and (
                not isinstance(origin, dict) or origin.get('kind') not in ORIGIN_KINDS or
                not isinstance(origin.get('reference'), str) or
                any(
                    not isinstance(key, str) or
                    not isinstance(value, (str, int, bool, type(None)))
                    for key, value in origin.items()
                )
            ):
                raise ValueError('record origin is invalid')
        elif 'image_os' in record or 'origin' in record:
            raise ValueError('record schema does not carry origin fields')
        if record.get('container_name') != f'freecore-app-{name}':
            raise ValueError('container name is not middleware-owned')
        container_id = record.get('container_id')
        if not (
            allow_unbound_container and container_id is None or
            isinstance(container_id, str) and re.fullmatch(CONTAINER_ID, container_id)
        ):
            raise ValueError('container ID is not an immutable Podman identity')

        image = record.get('image')
        image_id = record.get('image_id')
        if not isinstance(image, str) or not isinstance(image_id, str):
            raise TypeError('image reference and ID must be strings')
        validate_image_reference(image)
        validate_image_reference(image_id)
        digest = record.get('digest')
        if not isinstance(digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            raise ValueError('image digest must be an immutable sha256 digest')
        if '@' in image and image.rsplit('@', 1)[1] != digest:
            raise ValueError('image reference and recorded digest do not match')
        if record.get('restart_policy') not in {'no', 'on-failure', 'always'}:
            raise ValueError('invalid restart policy')

        # the internal development record: schema 4 records carry their network attachment.
        network = record.get('network')
        if schema >= 4:
            if not isinstance(network, dict) or network.get('mode') not in {'managed', 'lan'}:
                raise ValueError('record network mode is invalid')
            if network['mode'] == 'managed':
                if set(network) == {'mode', 'bridge_address'}:
                    # the internal development record: the pinned address on the managed bridge.
                    ApplicationsService._check_bridge_pin(config, network['bridge_address'])
                elif set(network) != {'mode'}:
                    raise ValueError('managed network carries no attachment fields')
            else:
                base_fields = {'mode', 'interface', 'address', 'gateway'}
                if set(network) == base_fields:
                    dual = False
                elif set(network) == base_fields | {'managed_access', 'managed_address'}:
                    dual = True
                else:
                    raise ValueError('LAN network attachment fields are invalid')
                if not isinstance(network['interface'], str) or not LAN_INTERFACE.fullmatch(
                    network['interface']
                ):
                    raise ValueError('LAN network interface is invalid')
                if not isinstance(network['address'], str) or not isinstance(network['gateway'], str):
                    raise TypeError('LAN network addressing must be strings')
                try:
                    attachment = ipaddress.IPv4Interface(network['address'])
                    gateway = ipaddress.IPv4Address(network['gateway'])
                except ValueError as error:
                    raise ValueError('LAN network addressing is invalid') from error
                if str(attachment) != network['address'] or str(gateway) != network['gateway']:
                    raise ValueError('LAN network addressing is not normalized')
                if attachment.network.prefixlen > 30 or attachment.ip in (
                    attachment.network.network_address, attachment.network.broadcast_address,
                ):
                    raise ValueError('LAN network address is not a usable host address')
                if gateway not in attachment.network or gateway == attachment.ip:
                    raise ValueError('LAN network gateway is outside the attached network')
                # the internal development record: the managed-bridge leg of a gateway.
                if dual:
                    if network['managed_access'] is not True:
                        raise ValueError('LAN managed access must be explicit')
                    ApplicationsService._check_bridge_pin(config, network['managed_address'])
        elif network is not None:
            raise ValueError('record schema does not carry a network attachment')
        if not all(isinstance(record.get(field), str) for field in ('created_at', 'updated_at')):
            raise ValueError('record timestamps must be strings')

        for field in ('ports', 'environment', 'volumes', 'annotations'):
            if not isinstance(record.get(field), list):
                raise TypeError(f'{field} must be a list')
            if len(record[field]) > DECLARATION_LIMITS[field]:
                raise ValueError(f'too many {field} declarations')

        # the internal development record: runtime options, absent from records written before them.
        runtime = record.get('runtime')
        if runtime is not None:
            if not isinstance(runtime, dict) or set(runtime) - RUNTIME_FIELDS:
                raise ValueError('runtime options are invalid')
            stop_timeout = runtime.get('stop_timeout')
            if stop_timeout is not None and (
                type(stop_timeout) is not int or not 0 <= stop_timeout <= MAX_STOP_TIMEOUT
            ):
                raise ValueError('runtime stop_timeout is invalid')
            # the internal development record: exactly the canonical form install writes, so nothing reaches
            # podman's --add-host unchecked.
            if 'extra_hosts' in runtime:
                try:
                    canonical = runtime_options({'extra_hosts': runtime['extra_hosts']})
                except CallError:
                    canonical = None
                if canonical != {'extra_hosts': runtime['extra_hosts']}:
                    raise ValueError('runtime extra_hosts is invalid')

        # the internal development record: labels arrived after records were already on disk, so a record
        # without the key is an older one and carries none -- it must still validate.
        labels = record.get('labels')
        if labels is None:
            labels = []
        if not isinstance(labels, list):
            raise TypeError('labels must be a list')
        if len(labels) > DECLARATION_LIMITS['labels']:
            raise ValueError('too many labels declarations')

        # the internal development record: certificates arrived after records were already on disk,
        # so a record without the key is an older one and mounts none.
        mounted_certificates = record.get('certificates')
        if mounted_certificates is None:
            mounted_certificates = []
        if not isinstance(mounted_certificates, list):
            raise TypeError('certificates must be a list')
        if len(mounted_certificates) > DECLARATION_LIMITS['certificates']:
            raise ValueError('too many certificates declarations')

        for item in record['ports']:
            # the internal development record: a null host port keeps the port on the managed bridge.
            if (
                not isinstance(item, dict) or
                'host_port' not in item or
                not (item['host_port'] is None or (
                    type(item['host_port']) is int and 1 <= item['host_port'] <= 65535
                )) or
                type(item.get('container_port')) is not int or
                not 1 <= item['container_port'] <= 65535 or
                item.get('protocol') not in {'tcp', 'udp'}
            ):
                raise ValueError('invalid declared port')

        for item in record['environment']:
            if (
                not isinstance(item, dict) or
                not isinstance(item.get('name'), str) or
                not re.fullmatch(ENVIRONMENT_NAME, item['name']) or
                not isinstance(item.get('value'), str) or
                not re.fullmatch(ENVIRONMENT_VALUE, item['value']) or
                len(item['value']) > 65536
            ):
                raise ValueError('invalid environment declaration')

        paths = application_paths(config['pool'])
        owned_prefix = f'{paths["data_dataset"]}/{name}/'
        for item in record['volumes']:
            if not isinstance(item, dict):
                raise TypeError('invalid volume declaration')
            dataset = item.get('dataset')
            source = item.get('source')
            target = item.get('target')
            if (
                not isinstance(item.get('name'), str) or
                not re.fullmatch(APPLICATION_NAME, item['name']) or
                not isinstance(dataset, str) or
                not re.fullmatch(DATASET_NAME, dataset) or
                not isinstance(source, str) or
                not source.startswith('/mnt/') or
                ':' in source or
                '\x00' in source or
                os.path.normpath(source) != source or
                not isinstance(target, str) or
                type(item.get('owned')) is not bool or
                type(item.get('read_only')) is not bool
            ):
                raise ValueError('invalid volume declaration')
            validate_mount_target(target)
            if item['owned']:
                if not dataset.startswith(owned_prefix) or source != f'/mnt/{dataset}':
                    raise ValueError('owned volume escapes its application dataset')
            elif len(dataset.split('/')) > 1 and dataset.split('/')[1] in {
                'applications', 'bastille', 'iocage'
            }:
                raise ValueError('external volume overlaps a managed hierarchy')

        # the internal development record: a certificate directory may not sit inside a volume
        # (it would create a directory in the operator's data) nor inside another entry.
        certificate_errors = app_certificates.validate_entries(
            mounted_certificates, [item['target'] for item in record['volumes']],
        )
        if certificate_errors:
            raise ValueError(f'invalid certificate declaration: {certificate_errors[0][1]}')

        for item in record['annotations']:
            if (
                not isinstance(item, dict) or
                not isinstance(item.get('name'), str) or
                not re.fullmatch(ANNOTATION_NAME, item['name']) or
                item['name'] in NETWORK_OWNED_ANNOTATIONS or
                not isinstance(item.get('value'), str) or
                not re.fullmatch(ANNOTATION_VALUE, item['value']) or
                len(item['value']) > 4096 or
                item['value'] not in CATALOG_RUNTIME_ANNOTATIONS.get(item['name'], set())
            ):
                raise ValueError('invalid jail annotation')

        for item in labels:
            if (
                not isinstance(item, dict) or
                not isinstance(item.get('name'), str) or
                not re.fullmatch(LABEL_NAME, item['name']) or
                item['name'].startswith(RESERVED_LABEL_PREFIX) or
                not isinstance(item.get('value'), str) or
                not re.fullmatch(LABEL_VALUE, item['value']) or
                len(item['value'].encode()) > 4096
            ):
                raise ValueError('invalid container label')

        portal = record.get('portal')
        if portal is not None and (
            not isinstance(portal, dict) or
            portal.get('scheme') not in {'http', 'https'} or
            type(portal.get('port')) is not int or
            not 1 <= portal['port'] <= 65535 or
            not isinstance(portal.get('path'), str) or
            not re.fullmatch(PORTAL_PATH, portal['path']) or
            len(portal['path']) > 2048
        ):
            raise ValueError('invalid portal declaration')

        healthcheck = record.get('healthcheck')
        if healthcheck is not None:
            if (
                not isinstance(healthcheck, dict) or
                set(healthcheck) != {
                    'container_port', 'host_port', 'path', 'scheme', 'type',
                } or
                healthcheck.get('type') != 'HTTP' or
                healthcheck.get('scheme') != 'http' or
                type(healthcheck.get('container_port')) is not int or
                not (healthcheck['host_port'] is None or (
                    type(healthcheck['host_port']) is int and 1 <= healthcheck['host_port'] <= 65535
                )) or
                not 1 <= healthcheck['container_port'] <= 65535 or
                not isinstance(healthcheck.get('path'), str) or
                not re.fullmatch(PORTAL_PATH, healthcheck['path']) or
                len(healthcheck['path']) > 2048 or
                not any(
                    port == {
                        'host_port': healthcheck['host_port'],
                        'container_port': healthcheck['container_port'],
                        'protocol': 'tcp',
                    }
                    for port in record['ports']
                )
            ):
                raise ValueError('invalid declared health check')
            # the internal development record: a health check on a bridge-only port is probed
            # at the pinned bridge address (#484); a LAN attachment probes its own.
            attachment = record.get('network') or {'mode': 'managed'}
            if (
                healthcheck['host_port'] is None and attachment.get('mode') != 'lan' and
                not attachment.get('bridge_address')
            ):
                raise ValueError('an unpublished health check port needs a pinned bridge address')

        catalog = record.get('catalog')
        if catalog is not None:
            if not isinstance(catalog, dict):
                raise ValueError('invalid catalog provenance')
            match = re.fullmatch(r'daemonless:([a-z0-9][a-z0-9_.-]{0,62})', catalog['id']) \
                if isinstance(catalog.get('id'), str) else None
            if (
                match is None or
                catalog.get('repository') != f'https://github.com/daemonless/{match.group(1)}' or
                not isinstance(catalog.get('version'), str) or
                not 1 <= len(catalog['version']) <= 128 or
                not isinstance(catalog.get('compose_sha256'), str) or
                not re.fullmatch(r'[0-9a-f]{64}', catalog['compose_sha256'])
            ):
                raise ValueError('invalid catalog provenance')
            if set(catalog) == LEGACY_CATALOG_FIELDS:
                # Written by the retired signed-snapshot client (the internal development record).
                # Accepted unchanged so an installed application survives the update
                # without a re-pull or a rewrite of its record.
                if (
                    type(catalog.get('entry_revision')) is not int or
                    not 1 <= catalog['entry_revision'] <= 2 ** 31 - 1 or
                    type(catalog.get('snapshot_sequence')) is not int or
                    not 1 <= catalog['snapshot_sequence'] <= 2 ** 63 - 1 or
                    not isinstance(catalog.get('source_commit'), str) or
                    not re.fullmatch(r'[0-9a-f]{40}', catalog['source_commit']) or
                    not isinstance(catalog.get('object_sha256'), str) or
                    not re.fullmatch(r'[0-9a-f]{64}', catalog['object_sha256'])
                ):
                    raise ValueError('invalid catalog provenance')
            elif set(catalog) - OPTIONAL_CATALOG_FIELDS == CATALOG_FIELDS:
                if not isinstance(catalog.get('image_tag'), str):
                    raise ValueError('invalid catalog provenance')
                validate_image_reference(catalog['image_tag'])
                # the internal development record: the pulled image's flavour label; records
                # written by 15.1-RC2 have none.
                variant = catalog.get('variant')
                if variant is not None and (
                    not isinstance(variant, str) or
                    not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', variant)
                ):
                    raise ValueError('invalid catalog provenance')
            else:
                raise ValueError('invalid catalog provenance')

        return record

    def _read_records(self, config):
        records = []
        errors = []
        records_path = Path(application_paths(config['pool'])['records'])
        if not records_path.is_dir():
            return records, errors

        for path in sorted(records_path.glob('*.json')):
            try:
                if path.stat().st_size > MAX_RECORD_SIZE:
                    raise ValueError('record exceeds the maximum supported size')
                record = json.loads(path.read_text())
                records.append(self._validate_record(config, record, path.stem))
            except (KeyError, OSError, TypeError, ValueError) as error:
                errors.append({
                    'name': path.stem,
                    'status': 'ERROR',
                    'error': f'Invalid managed record: {error}',
                })
        return records, errors

    def _write_record(self, config, record):
        path = os.path.join(application_paths(config['pool'])['records'], f'{record["name"]}.json')
        atomic_write(path, json.dumps(record, indent=2, sort_keys=True) + '\n')

    def _delete_record(self, config, name):
        path = os.path.join(application_paths(config['pool'])['records'], f'{name}.json')
        os.unlink(path)

    def _get_record(self, config, name):
        records, errors = self._read_records(config)
        for record in records:
            if record['name'] == name:
                return record
        for error in errors:
            if error['name'] == name:
                raise CallError(error['error'])
        raise CallError(f'Application {name!r} does not exist.', errno.ENOENT)

    async def _podman(self, config, *arguments, check=True, redactions=()):
        if arguments and arguments[0] in PODMAN_NETWORK_OPERATIONS:
            await self._reserve_jail_bridge()
        environment = os.environ.copy()
        environment.update(podman_environment(config['pool']))
        cp = await run(
            [PODMAN_PATH, *arguments],
            check=False,
            encoding='utf8',
            env=environment,
        )
        if check and cp.returncode:
            operation = arguments[0] if arguments else 'command'
            detail = (cp.stderr or cp.stdout or '').strip()[-4096:]
            secrets = list(redactions)
            for index, argument in enumerate(arguments[:-1]):
                if argument == '--env' and '=' in arguments[index + 1]:
                    secrets.append(arguments[index + 1].split('=', 1)[1])
            for secret in secrets:
                if secret:
                    detail = detail.replace(secret, '********')
            raise CallError(f'Podman {operation} failed: {detail}')
        return cp

    async def _container_exists(self, config, name):
        result = await self._podman(config, 'container', 'exists', name, check=False)
        if result.returncode not in (0, 1):
            raise CallError(
                f'Unable to determine whether application container {name!r} exists '
                f'(Podman exit status {result.returncode}).'
            )
        return result.returncode == 0

    async def _image_exists(self, config, image):
        return (await self._podman(config, 'image', 'exists', image, check=False)).returncode == 0

    async def _inspect_container(self, config, name):
        cp = await self._podman(config, 'container', 'inspect', name)
        data = json.loads(cp.stdout)
        return data[0] if isinstance(data, list) else data

    async def _inspect_image(self, config, image, allow_linux=False):
        cp = await self._podman(config, 'image', 'inspect', image)
        data = json.loads(cp.stdout)
        info = data[0] if isinstance(data, list) else data
        image_os = (info.get('Os') or info.get('OS') or '').lower()
        # the internal development record: a Linux image is accepted only when the caller
        # asked for one and the experimental compatibility tier is on.
        if image_os != 'freebsd' and not (image_os == 'linux' and allow_linux):
            raise CallError(
                f'Applications accepts native FreeBSD images; image reports OS {image_os or "unknown"!r}.'
            )
        repo_digests = info.get('RepoDigests') or []
        digest = info.get('Digest') or ''
        if not digest and repo_digests and '@' in repo_digests[0]:
            digest = repo_digests[0].rsplit('@', 1)[1]
        labels = (info.get('Config') or {}).get('Labels') or info.get('Labels') or {}
        env = (info.get('Config') or {}).get('Env') or info.get('Env') or []
        return {
            'id': info.get('Id') or info.get('ID') or image,
            'digest': digest,
            'os': image_os,
            'labels': labels if isinstance(labels, dict) else {},
            # the internal development record: the image's own PUID/PGID, for the volumes this install creates.
            'env': [item for item in env if isinstance(item, str)] if isinstance(env, list) else [],
        }

    async def _catalog_states(self, records, observed=None):
        """One catalog answer per record.  ``observed`` (the internal development record)
        is what each record's running image says it is, read from the container
        inspection the page already has; it outranks the record's own memory."""
        try:
            states = await self.middleware.call(
                'applications.catalog.installed_state',
                [record.get('catalog') for record in records],
                observed if observed is not None else [None for _ in records],
            )
            if not isinstance(states, list) or len(states) != len(records):
                raise CallError('Applications catalog returned invalid installed state.')
            return states
        except Exception as error:
            self.logger.warning('Unable to resolve installed Applications catalog state', exc_info=True)
            return [{
                'update_available': False,
                'revoked': False,
                'revocation_reason': None,
                'catalog_error': str(error),
            } for _ in records]

    @filterable
    async def query(self, filters=None, options=None):
        config = await self.config()
        if not config['pool']:
            return filter_list([], filters, options)

        records, errors = self._read_records(config)
        if not config['runtime_ready']:
            catalog_states = await self._catalog_states(records)
            result = []
            for record, catalog_state in zip(records, catalog_states):
                item = public_record(record)
                item.update(catalog_state)
                item.update({
                    'status': 'UNAVAILABLE',
                    'running': False,
                    'restarts': 0,
                    'exit_code': None,
                    'health_declared': record.get('healthcheck') is not None,
                    'health': (
                        'UNKNOWN' if record.get('healthcheck') is not None else 'UNDECLARED'
                    ),
                    'error': 'Applications runtime prerequisites are not ready on this controller.',
                    'bridge_address': next(iter(self._bridge_pins(record)), None),
                })
                result.append(item)
            result.extend(errors)
            return filter_list(result, filters, options)

        result = []
        inspected = await self._inspect_managed_containers(config, records)
        observed = [self._observed_image_version(inspected.get(record['name'])) for record in records]
        catalog_states = await self._catalog_states(records, observed)
        for record, catalog_state, seen in zip(records, catalog_states, observed):
            item = public_record(record)
            item.update(catalog_state)
            if seen is not None and isinstance(item.get('catalog'), dict):
                # The installed version is what the running image says, not what
                # the review could read from the index when the record was written.
                item['catalog'].update({
                    'version': seen[0],
                    'variant': seen[1] if seen[1] is not None else item['catalog'].get('variant'),
                    'version_source': 'image',
                })
            try:
                owned = inspected.get(record['name'])
                if isinstance(owned, CallError):
                    raise owned
                if owned is None:
                    raise CallError(
                        f'Managed container {record["container_name"]!r} is unavailable.'
                    )
                inspection = owned[0]
            except (CallError, KeyError, TypeError, ValueError) as error:
                item.update({
                    'status': 'MISSING',
                    'running': False,
                    'restarts': 0,
                    'exit_code': None,
                    'health_declared': record.get('healthcheck') is not None,
                    'health': (
                        'UNKNOWN' if record.get('healthcheck') is not None else 'UNDECLARED'
                    ),
                    'error': str(error),
                    'bridge_address': next(iter(self._bridge_pins(record)), None),
                })
            else:
                state = inspection.get('State') or {}
                health = state.get('Health') or {}
                health_status = health.get('Status') or health.get('status')
                if record.get('healthcheck') is None:
                    health_status = 'UNDECLARED'
                elif not health_status:
                    health_status = 'UNKNOWN'
                item.update(self._classify_state(record, inspection))
                item.update({
                    'health_declared': record.get('healthcheck') is not None,
                    'health': str(health_status).upper(),
                    'bridge_address': self._bridge_address(record, inspection),
                })
            result.append(item)
        result.extend(errors)
        return filter_list(result, filters, options)

    @staticmethod
    def _observed_image_version(owned):
        """``(version, variant)`` from a container inspection's labels -- podman
        carries the image's labels into the container's config -- or None."""
        if not isinstance(owned, tuple) or not owned or not isinstance(owned[0], dict):
            return None
        labels = (owned[0].get('Config') or {}).get('Labels')
        version, variant = image_version(labels)
        return (version, variant) if version is not None else None

    async def _reserved_management_ports(self):
        general = await self.middleware.call('system.general.config')
        ssh = await self.middleware.call('ssh.config')
        return {
            (general['ui_port'], 'tcp'),
            (general['ui_httpsport'], 'tcp'),
            (ssh['tcpport'], 'tcp'),
        }

    @staticmethod
    def _port_available(port, protocol):
        socktype = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
        for family, address in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
            try:
                with socket.socket(family, socktype) as sock:
                    sock.bind((address, port))
            except OSError as error:
                if error.errno == errno.EADDRINUSE:
                    return False
                if error.errno in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
                    continue
                raise
        return True

    @staticmethod
    def _network_request(data):
        """The record network block an install or reconfigure request asks for."""
        network = data.get('network') or {'mode': 'managed'}
        if network.get('mode') != 'lan':
            return {'mode': 'managed'}
        request = {
            'mode': 'lan',
            'interface': network.get('interface'),
            'address': network.get('address'),
            'gateway': network.get('gateway'),
        }
        # the internal development record: the managed-leg address is assigned, never requested.
        if network.get('managed_access'):
            request['managed_access'] = True
        return request

    @staticmethod
    def _managed_subnet(config):
        # The settings row always carries the subnet; its column default is DEFAULT_SUBNET.
        return ipaddress.ip_network(config.get('subnet') or DEFAULT_SUBNET, strict=True)

    @staticmethod
    def _check_bridge_pin(config, value):
        """A pinned managed-bridge address: normalized IPv4 inside the usable managed subnet."""
        managed = ApplicationsService._managed_subnet(config)
        try:
            address = ipaddress.IPv4Address(value)
        except (TypeError, ValueError) as error:
            raise ValueError('pinned bridge address is invalid') from error
        if str(address) != value:
            raise ValueError('pinned bridge address is not normalized')
        if address not in managed or address in (
            managed.network_address, managed.broadcast_address, managed.network_address + 1,
        ):
            raise ValueError('pinned bridge address is outside the usable managed subnet')

    @staticmethod
    def _bridge_pins(record):
        network = record.get('network') or {}
        return [
            value for value in (network.get('bridge_address'), network.get('managed_address'))
            if isinstance(value, str)
        ]

    @staticmethod
    def _allocate_managed_leg_address(config, records, current_name=None):
        """A stable managed-subnet address -- a dual attachment's leg (#482) or a
        managed application's pin (#484) -- assigned from the top of the subnet
        downward.  Podman's host-local allocator grows from the bottom for the
        transient containers (migration hops, lift builds) that remain dynamic."""
        managed = ApplicationsService._managed_subnet(config)
        taken = set()
        for record in records:
            if record['name'] == current_name:
                continue
            for value in ApplicationsService._bridge_pins(record):
                with contextlib.suppress(ValueError):
                    taken.add(ipaddress.IPv4Address(value))
        candidate = managed.broadcast_address - 1
        floor = managed.network_address + 2
        for _ in range(512):
            if candidate < floor:
                break
            if candidate not in taken:
                return str(candidate)
            candidate -= 1
        raise CallError('No managed-bridge address is free for the LAN attachment.')

    @staticmethod
    def _bridge_address(record, inspection):
        """The container's address on the managed bridge, for the row
        (the internal development record): the recorded leg for a dual attachment, the
        default network's address for a managed application, None otherwise."""
        network = record.get('network') or {}
        if network.get('mode') == 'lan':
            return network.get('managed_address')
        pinned = network.get('bridge_address')
        settings = (inspection or {}).get('NetworkSettings') or {}
        entry = (settings.get('Networks') or {}).get('podman')
        address = entry.get('IPAddress') if isinstance(entry, dict) else None
        if not address:
            address = settings.get('IPAddress')
        try:
            return str(ipaddress.IPv4Address(address)) if address else pinned
        except ValueError:
            return pinned

    @staticmethod
    def _jail_address_addresses(jail):
        addresses = []
        for field in ('ip4_addr', 'ip6_addr'):
            for value in str(jail.get(field) or '').split(','):
                value = value.strip()
                if '|' in value:
                    value = value.rsplit('|', 1)[1]
                if not value or value.lower() in {'none', 'dhcp', 'accept_rtadv'}:
                    continue
                try:
                    addresses.append(ipaddress.ip_interface(value).ip)
                except ValueError:
                    continue
        return addresses

    async def _defined_jail_addresses(self):
        addresses = []
        methods = ['bastille.query']
        if await self.middleware.call('jail.get_activated_pool') is not None:
            methods.insert(0, 'jail.query')
        for method in methods:
            for jail in await self.middleware.call(method):
                addresses.extend(self._jail_address_addresses(jail))
        return addresses

    async def _validate_lan_network(self, verrors, prefix, config, network, records, current_name=None):
        """the internal development record: what a LAN attachment must satisfy.

        The DHCP pool of the attached network is invisible from here; keeping
        the address outside it is the administrator's part of the contract.
        """
        interface = network.get('interface')
        if not isinstance(interface, str) or not LAN_INTERFACE.fullmatch(interface):
            verrors.add(f'{prefix}.interface', 'A LAN attachment names the host interface to join.')
            interface = None
        attachment = None
        address = network.get('address')
        if isinstance(address, str) and '/' in address:
            try:
                attachment = ipaddress.IPv4Interface(address)
            except ValueError:
                attachment = None
        if attachment is not None and (
            attachment.network.prefixlen > 30 or attachment.ip in (
                attachment.network.network_address, attachment.network.broadcast_address,
            )
        ):
            attachment = None
        if attachment is None:
            verrors.add(
                f'{prefix}.address',
                'A LAN attachment needs a usable IPv4 host address with its prefix (address/nn).',
            )
        gateway = None
        try:
            gateway = ipaddress.IPv4Address(network.get('gateway'))
        except (TypeError, ValueError):
            verrors.add(f'{prefix}.gateway', 'A LAN attachment needs the IPv4 gateway of its network.')
        if attachment is not None and gateway is not None and (
            gateway not in attachment.network or gateway == attachment.ip
        ):
            verrors.add(
                f'{prefix}.gateway',
                'The gateway must live inside the attached network and differ from the address.',
            )

        if interface is not None:
            choices = await self.middleware.call(
                'interface.choices', {'exclude': ['epair', 'tap', 'vnet', 'lo', 'pflog']}
            )
            if interface not in choices:
                verrors.add(f'{prefix}.interface', f'Interface {interface!r} does not exist on this system.')

        if attachment is None:
            return
        managed = ipaddress.ip_network(config['subnet'], strict=True)
        if managed.version == 4 and attachment.ip in managed:
            verrors.add(f'{prefix}.address', 'The address lies inside the managed container subnet.')
        for record in records:
            if record['name'] == current_name:
                continue
            other = record.get('network') or {}
            if other.get('mode') != 'lan':
                continue
            try:
                other_address = ipaddress.IPv4Interface(other['address']).ip
            except (KeyError, ValueError):
                continue
            if other_address == attachment.ip:
                verrors.add(
                    f'{prefix}.address',
                    f'The address is already attached by application {record["name"]!r}.',
                )
        in_use = await self.middleware.call('interface.ip_in_use', {'ipv4': True, 'ipv6': False})
        if str(attachment.ip) in {item.get('address') for item in in_use}:
            verrors.add(f'{prefix}.address', 'The address is already configured on this host.')
        if attachment.ip in set(await self._defined_jail_addresses()):
            verrors.add(f'{prefix}.address', 'The address is already assigned to a defined jail.')

    async def _ensure_lan_bridge(self, interface):
        """The bridge that carries ``interface`` (the internal development record).

        Delegated to ``interface.ensure_jail_bridge``: a member already in
        exactly one jail-named bridge keeps it (jail-first, VM-created,
        repeat starts), otherwise the lowest unassigned runtime slot --
        ``bridge0`` first -- takes the uplink.  iocage's own later ``addm``
        on ``bridge0`` is then the already-exists case it ignores, so the
        13.3 "first claimant, everyone shares" convention holds; a second
        physical uplink gets the next slot, never a shared bridge, so two
        LANs cannot be bridged together; and with no free slot the start
        refuses instead of stranding later jails on an uplink-less bridge.
        """
        return await self._settle_before_reraise(
            self.middleware.call('interface.ensure_jail_bridge', interface)
        )

    async def _prepare_lan_network(self, config, record):
        """Render the application's CNI network against the bridge that exists now.

        Runs before every network-touching start of a LAN-attached application,
        so a bridge recreated since the last boot heals into the conflist.
        Returns what the conflist held before, for rollback.
        """
        network = record.get('network') or {}
        if network.get('mode') != 'lan':
            return None
        bridge = await self._ensure_lan_bridge(network['interface'])
        path = lan_conflist_path(config['pool'], record['name'])
        try:
            previous = Path(path).read_text(encoding='utf8')
        except FileNotFoundError:
            previous = None
        atomic_write(path, render_lan_conflist(
            record['name'], bridge, network['address'], network['gateway'],
        ))
        managed_path = lan_managed_conflist_path(config['pool'], record['name'])
        try:
            managed_previous = Path(managed_path).read_text(encoding='utf8')
        except FileNotFoundError:
            managed_previous = None
        if network.get('managed_access'):
            # the internal development record: create-if-missing is CORRECT for this leg --
            # a bare managed bridge is exactly what podman itself would create.
            prefixlen = ipaddress.ip_network(config['subnet'], strict=True).prefixlen
            atomic_write(managed_path, render_managed_leg_conflist(
                record['name'], CNI_BRIDGE, f'{network["managed_address"]}/{prefixlen}',
            ))
        else:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(managed_path)
        return {'lan': previous, 'managed': managed_previous}

    def _restore_lan_conflist(self, pool, application, previous):
        previous = previous or {}
        for key, path in (
            ('lan', lan_conflist_path(pool, application)),
            ('managed', lan_managed_conflist_path(pool, application)),
        ):
            content = previous.get(key)
            if content is None:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path)
            else:
                atomic_write(path, content)

    def _remove_lan_conflist(self, pool, application):
        for path in (
            lan_conflist_path(pool, application),
            lan_managed_conflist_path(pool, application),
        ):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)

    @staticmethod
    def _record_healthcheck_probe(record):
        """The health probe the record's network mode allows.

        A managed application is probed through its published host port; a
        LAN-attached application publishes nothing, so the probe goes to its
        own address and container port.  A managed health check port kept on
        the bridge (the internal development record) is probed the same way, at the
        pinned bridge address.
        """
        healthcheck = record.get('healthcheck')
        if healthcheck is None:
            return None
        network = record.get('network') or {}
        if network.get('mode') != 'lan':
            if healthcheck['host_port'] is not None:
                return healthcheck
            return {
                **healthcheck,
                'probe_host': network['bridge_address'],
                'probe_port': healthcheck['container_port'],
            }
        return {
            **healthcheck,
            'probe_host': str(ipaddress.IPv4Interface(network['address']).ip),
            'probe_port': healthcheck['container_port'],
        }

    async def _validate_install(self, config, data):
        verrors = ValidationErrors()
        network = self._network_request(data)
        for field, limit in DECLARATION_LIMITS.items():
            # 'labels' (the internal development record) may be absent from a hand-built payload.
            if len(data.get(field) or []) > limit:
                verrors.add(
                    f'application_install.{field}',
                    f'At most {limit} {field} declarations are supported.',
                )
        try:
            validate_image_reference(data['image'])
        except ValueError as error:
            verrors.add('application_install.image', str(error))

        records, _ = self._read_records(config)
        if any(record['name'] == data['name'] for record in records):
            verrors.add('application_install.name', 'An application with this name already exists.')

        container_name = f'freecore-app-{data["name"]}'
        if await self._container_exists(config, container_name):
            verrors.add(
                'application_install.name',
                f'Podman container {container_name!r} already exists and is not available for adoption.',
            )

        environment_names = [item['name'] for item in data['environment']]
        if len(environment_names) != len(set(environment_names)):
            verrors.add('application_install.environment', 'Environment variable names must be unique.')

        annotation_names = [item['name'] for item in data['annotations']]
        if len(annotation_names) != len(set(annotation_names)):
            verrors.add('application_install.annotations', 'Annotation names must be unique.')
        for index, annotation in enumerate(data['annotations']):
            if annotation['name'] in NETWORK_OWNED_ANNOTATIONS:
                verrors.add(
                    f'application_install.annotations.{index}.name',
                    'This annotation is owned by the managed container network.',
                )
            elif annotation['value'] not in CATALOG_RUNTIME_ANNOTATIONS.get(annotation['name'], set()):
                verrors.add(
                    f'application_install.annotations.{index}',
                    'This annotation is not permitted for catalog applications.',
                )

        requested_labels = data.get('labels') or []
        label_names = [item['name'] for item in requested_labels]
        if len(label_names) != len(set(label_names)):
            verrors.add('application_install.labels', 'Label names must be unique.')
        for index, label in enumerate(requested_labels):
            if label['name'].startswith(RESERVED_LABEL_PREFIX):
                verrors.add(
                    f'application_install.labels.{index}.name',
                    f'Names beginning with {RESERVED_LABEL_PREFIX} are reserved for '
                    "FreeCORE's own management labels.",
                )
            if len(label['value'].encode()) > 4096:
                verrors.add(
                    f'application_install.labels.{index}.value',
                    'A label value may be at most 4096 bytes.',
                )

        # the internal development record: structure and target rules first, then the store.
        requested_certificates = data.get('certificates') or []
        for schema, message in app_certificates.validate_entries(
            requested_certificates, [item['target'] for item in data['volumes']],
            prefix='application_install.certificates',
        ):
            verrors.add(schema, message)
        for index, entry in enumerate(requested_certificates):
            if type(entry.get('id')) is not int:
                continue
            # The same health rules the host services apply: a complete, unrevoked
            # certificate with a usable private key. Expiry is not one of them.
            verrors.extend(await self.middleware.call(
                'certificate.cert_services_validation', entry['id'],
                f'application_install.certificates.{index}.id', False,
            ))
            certificate = await self.middleware.call(
                'certificate.query', [['id', '=', entry['id']]],
            )
            if not certificate:
                continue
            certificate = certificate[0]
            if (
                certificate.get('name') != entry.get('name') or
                certificate.get('fingerprint') != entry.get('fingerprint')
            ):
                verrors.add(
                    f'application_install.certificates.{index}.fingerprint',
                    'This certificate changed since the form was opened; review it again.',
                )

        volume_names = [item['name'] for item in data['volumes']]
        volume_targets = [item['target'] for item in data['volumes']]
        if len(volume_names) != len(set(volume_names)):
            verrors.add('application_install.volumes', 'Volume names must be unique.')
        if len(volume_targets) != len(set(volume_targets)):
            verrors.add('application_install.volumes', 'Volume targets must be unique.')
        for index, volume in enumerate(data['volumes']):
            try:
                validate_mount_target(volume['target'])
            except ValueError as error:
                verrors.add(f'application_install.volumes.{index}.target', str(error))

        # the internal development record: a port without a host port is not published, so it
        # holds no host port and takes no part in the host-port rules below.
        requested_ports = [
            (item['host_port'], item['protocol']) for item in data['ports']
            if item['host_port'] is not None
        ]
        if len(requested_ports) != len(set(requested_ports)):
            verrors.add('application_install.ports', 'Host port/protocol pairs must be unique.')

        used_ports = {
            (port['host_port'], port['protocol'])
            for record in records
            # the internal development record: a LAN-attached application publishes nothing.
            if (record.get('network') or {}).get('mode') != 'lan'
            for port in record.get('ports', [])
            if port['host_port'] is not None
        }
        if network['mode'] == 'lan':
            await self._validate_lan_network(
                verrors, 'application_install.network', config, network, records,
            )
            host_ports_to_check = []
            reserved = set()
        else:
            host_ports_to_check = data['ports']
            reserved = await self._reserved_management_ports()
        for index, port in enumerate(host_ports_to_check):
            if port['host_port'] is None:
                continue
            key = (port['host_port'], port['protocol'])
            if key in used_ports:
                verrors.add(
                    f'application_install.ports.{index}.host_port',
                    'Host port is already assigned to a managed application.',
                )
            elif key in reserved:
                verrors.add(
                    f'application_install.ports.{index}.host_port',
                    'Host port is reserved for appliance management.',
                )
            elif not await self.middleware.run_in_thread(
                self._port_available, port['host_port'], port['protocol']
            ):
                verrors.add(
                    f'application_install.ports.{index}.host_port',
                    'Host port is already in use.',
                )

        if data['portal'] and data['portal']['port'] not in {
            port['host_port'] for port in data['ports']
            if port['protocol'] == 'tcp' and port['host_port'] is not None
        }:
            verrors.add(
                'application_install.portal.port',
                'Portal port must reference a declared TCP host port.',
            )

        verrors.check()

    # the internal development record: an `id =` lookup takes zfs.dataset.query's fast path,
    # but that path serialises the whole subtree with every property unless told
    # not to.  Under the Applications graphroot that is one dataset per image
    # layer, and an existence check came back as 3 MB after 17 seconds.
    async def _dataset_exists(self, dataset):
        return bool(await self.middleware.call(
            'zfs.dataset.query', [('id', '=', dataset)],
            {'extra': {'recursive': False, 'retrieve_properties': False}},
        ))

    async def _dataset_mountpoint(self, dataset):
        """The configured mountpoint of one dataset, or None when it does not exist."""
        matches = await self.middleware.call(
            'zfs.dataset.query', [('id', '=', dataset)],
            {'extra': {'recursive': False, 'properties': ['mountpoint'], 'user_properties': False}},
        )
        if not matches:
            return None
        mountpoint = matches[0].get('mountpoint')
        if not mountpoint:
            mountpoint = ((matches[0].get('properties') or {}).get('mountpoint') or {}).get('value')
        return mountpoint or None

    async def _mark_store_opaque(self, dataset):
        """the internal development record: the graphroot's children are podman's image layers.

        Marked once (idempotent, also for stores created before the property
        existed) so dataset enumeration shows the store as one leaf.
        """
        try:
            cp = await run(
                ['zfs', 'get', '-H', '-s', 'local', '-o', 'value', OPAQUE_PROPERTY, dataset],
                check=False, encoding='utf8',
            )
            if cp.returncode == 0 and cp.stdout.strip() == 'on':
                return
            cp = await run(['zfs', 'set', f'{OPAQUE_PROPERTY}=on', dataset], check=False, encoding='utf8')
        except OSError as error:
            self.logger.warning('Unable to mark %s opaque: %s', dataset, error)
            return
        if cp.returncode:
            self.logger.warning('Unable to mark %s opaque: %s', dataset, (cp.stderr or '').strip()[-256:])
            return
        try:
            await self.middleware.call('zfs.dataset.forget_opaque_datasets')
        except Exception:  # noqa: BLE001
            pass

    async def _dataset_owner(self, dataset):
        cp = await run(
            ['zfs', 'get', '-H', '-o', 'value,source', MANAGED_PROPERTY, dataset],
            check=False,
            encoding='utf8',
        )
        if cp.returncode:
            return None
        try:
            value, source = cp.stdout.strip().split('\t', 1)
        except ValueError:
            return None
        return value if value not in ('', '-') and source == 'local' else None

    @staticmethod
    def _declared_runtime_owner(environment):
        """The uid/gid an image says it will run as, or None if it does not say.

        the internal development record: PUID/PGID is the naming convention the catalog's
        images use, not a contract we can enforce, so an entry that declares neither
        keeps exactly the behaviour it has today. An explicit catalog field is the
        durable answer and is a schema change plus a signing session.
        """
        values = {
            item.get('name'): item.get('value')
            for item in (environment or [])
            if isinstance(item, dict)
        }
        try:
            uid = int(values['PUID'])
            gid = int(values['PGID'])
        except (KeyError, TypeError, ValueError):
            return None
        return (uid, gid) if uid >= 0 and gid >= 0 else None

    @classmethod
    def _image_runtime_owner(cls, image_env):
        """the internal development record: the uid/gid an image's own config says it runs as
        (``PUID``/``PGID`` in its ``Env``), by #438's rule; None if it does not say."""
        return cls._declared_runtime_owner([
            {'name': name, 'value': value}
            for name, _, value in (item.partition('=') for item in image_env or [])
        ])

    async def _give_new_volumes_to(self, volumes, created, runtime_owner):
        """the internal development record: hand the owned volumes this transaction created to the
        image's runtime user when the request named none. Docker and podman give a new named
        volume the image directory's owner; a fresh dataset mounts root-owned 0755 instead and
        hides it. Only datasets created right now, one directory each, never an external one."""
        for volume in volumes:
            if volume.get('owned') and volume['dataset'] in created:
                await self._chown_new_volume(volume['dataset'], runtime_owner)

    async def _chown_new_volume(self, dataset, runtime_owner):
        uid, gid = runtime_owner
        job = await self.middleware.call('filesystem.chown', {
            'path': f'/mnt/{dataset}',
            'uid': uid,
            'gid': gid,
            'options': {'recursive': False, 'traverse': False},
        })
        await job.wait()
        if job.error:
            raise CallError(
                f'Unable to give application volume {dataset!r} to uid {uid}: {job.error}'
            )

    async def _ensure_owned_dataset(self, dataset, owner, created, runtime_owner=None):
        if await self._dataset_exists(dataset):
            if await self._dataset_owner(dataset) != owner:
                raise CallError(f'Dataset {dataset!r} exists without expected Applications ownership.')
            # Deliberately not restamped: a volume that already exists may carry data
            # and permissions the operator has since adjusted.
            return

        created.append(dataset)
        await self._settle_before_reraise(self.middleware.call(
            'zfs.dataset.create', {
                'name': dataset,
                'properties': {
                    'atime': 'off',
                    'compression': 'lz4',
                    MANAGED_PROPERTY: owner,
                },
            }
        ))
        await self._settle_before_reraise(
            self.middleware.call('zfs.dataset.mount', dataset)
        )
        if runtime_owner is not None:
            # A new dataset mounts root-owned 0755, so a container running as anyone
            # else cannot write to the volume we just handed it. One directory, brand
            # new and empty: non-recursive, and never an external dataset.
            await self._chown_new_volume(dataset, runtime_owner)

    @staticmethod
    def _certificate_reference(entry, certificate):
        """Refuse a record whose entry is no longer bound to the certificate's key.

        the internal development record: records live on the pool, certificates in the
        configuration database. A pool imported on another system would otherwise
        mount whatever certificate happens to hold that id. The binding is the public
        key, not the name or the fingerprint: an ACME renewal re-orders with the stored
        CSR (new fingerprint, same key) and a rename changes only the name, and neither
        may leave the application without its files.
        """
        if certificate is None:
            raise CallError(
                f'Certificate {entry["name"]!r} (id {entry["id"]}) is no longer in the '
                'certificate store.'
            )
        expected = entry.get('public_key_sha256')
        if expected is None:
            # Bound before the key was recorded: the fingerprint is all there is.
            if certificate.get('fingerprint') != entry['fingerprint']:
                raise CallError(
                    f'Certificate id {entry["id"]} ({certificate.get("name")!r}) is not the '
                    f'certificate {entry["name"]!r} was bound to; remove it from the '
                    'application\'s certificates and choose it again.'
                )
            return certificate
        try:
            actual = app_certificates.public_key_sha256(certificate)
        except app_certificates.CertificateMountError as error:
            raise CallError(f'Certificate {entry["name"]!r} cannot be mounted: {error}') from error
        if actual != expected:
            raise CallError(
                f'Certificate id {entry["id"]} ({certificate.get("name")!r}) now holds a '
                'different key than the one this application was bound to; remove it from '
                'the application\'s certificates and choose it again.'
            )
        return certificate

    async def _bind_install_certificates(self, entries):
        """The record form of an install's entries, each bound to its certificate's key.

        the internal development record: ``_validate_install`` has already refused an entry whose
        certificate is gone or is no longer the one the form showed.
        """
        bound = []
        for entry in entries:
            found = await self.middleware.call('certificate.query', [['id', '=', entry['id']]])
            if not found:
                raise CallError(
                    f'Certificate {entry["name"]!r} (id {entry["id"]}) is no longer in the '
                    'certificate store.'
                )
            try:
                key = app_certificates.public_key_sha256(found[0])
            except app_certificates.CertificateMountError as error:
                raise CallError(f'Certificate {entry["name"]!r} cannot be mounted: {error}') from error
            bound.append(app_certificates.bound_entry({**entry, 'public_key_sha256': key}))
        return bound

    async def _bind_requested_certificates(self, current, requested, schema):
        """Bind an edit's certificate rows to the certificate store (the internal development record).

        The edit form sends each row with the name and fingerprint it holds. A row carried
        over from the record still has the ones it was bound with, which a renewal or a
        rename may since have changed in the store; a row chosen now has the store's own.
        Both bind to the certificate as it is now -- a carried-over row only while the key
        is still the one it was bound to, and a new binding only if it passes the rules the
        host services apply. Anything else is refused here, before the running container
        is touched.
        """
        verrors = ValidationErrors()
        previous = {}
        for entry in current.get('certificates') or []:
            previous.setdefault((entry.get('id'), entry.get('fingerprint')), entry)
        bound = []
        for index, entry in enumerate(requested):
            at = f'{schema}.{index}'
            found = await self.middleware.call('certificate.query', [['id', '=', entry['id']]])
            if not found:
                verrors.add(
                    f'{at}.id',
                    f'Certificate {entry["name"]!r} (id {entry["id"]}) is no longer in the '
                    'certificate store.',
                )
                continue
            certificate = found[0]
            try:
                key = app_certificates.public_key_sha256(certificate)
            except app_certificates.CertificateMountError as error:
                verrors.add(f'{at}.id', f'Certificate {certificate.get("name")!r} cannot be mounted: {error}')
                continue
            kept = previous.get((entry['id'], entry['fingerprint']))
            if certificate.get('fingerprint') == entry['fingerprint']:
                if kept is None or kept.get('public_key_sha256') != key:
                    # A new binding: the rules an install applies.
                    verrors.extend(await self.middleware.call(
                        'certificate.cert_services_validation', entry['id'], f'{at}.id', False,
                    ))
            elif kept is None:
                verrors.add(
                    f'{at}.fingerprint',
                    'This certificate changed since the form was opened; choose it again.',
                )
                continue
            elif kept.get('public_key_sha256') != key:
                verrors.add(
                    f'{at}.id',
                    f'Certificate id {entry["id"]} ({certificate.get("name")!r}) now holds a '
                    'different key than the one this application was bound to; remove it and '
                    'choose it again.',
                )
                continue
            bound.append({
                **entry,
                'name': certificate['name'],
                'fingerprint': certificate['fingerprint'],
                'public_key_sha256': key,
            })
        verrors.check()
        return bound

    def _write_certificate_files(self, directory, files, owner):
        """Render one entry's four files into ``directory``; returns True if anything changed.

        The directory itself is never replaced: it is the bind-mount source of a running
        container, so the files inside it are written to a temporary name and renamed.
        What is already mounted is the state a renewal is compared against -- nothing is
        stored beside the record, and a second pass over unchanged files restarts nothing.
        """
        uid, gid = owner
        os.makedirs(directory, mode=app_certificates.DIRECTORY_MODE, exist_ok=True)
        changed = False
        for name, text in files.items():
            path = os.path.join(directory, name)
            try:
                with open(path) as handle:
                    changed = changed or handle.read() != text
            except FileNotFoundError:
                changed = True
        for name, text in files.items():
            path = os.path.join(directory, name)
            descriptor, temporary = tempfile.mkstemp(prefix=f'.{name}-', dir=directory)
            try:
                with os.fdopen(descriptor, 'w') as handle:
                    handle.write(text)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, app_certificates.FILE_MODE)
                os.chown(temporary, uid, gid)
                os.rename(temporary, path)
            except BaseException:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary)
                raise
        # Recomputed on every render: an edit that changes PUID/PGID re-owns the directory.
        os.chmod(directory, app_certificates.DIRECTORY_MODE)
        os.chown(directory, uid, gid)
        for name in os.listdir(directory):
            if name not in app_certificates.FILE_NAMES:
                # A file from an earlier layout, or a temporary left by a crash.
                with contextlib.suppress(FileNotFoundError, IsADirectoryError):
                    os.unlink(os.path.join(directory, name))
        return changed

    def _remove_certificate_files(self, application):
        root = app_certificates.certificates_root(application)
        with contextlib.suppress(FileNotFoundError):
            shutil.rmtree(root)

    @private
    async def render_certificates(self, record):
        """Render every certificate the record mounts.

        Returns ``{'hash': …, 'changed': [index, …], 'restart': bool}``: what is mounted,
        which entries were rewritten by this pass, and whether any of those asked for a
        restart. Called before a container is created, before every start, at boot, and by
        the reconcile pass after a certificate changes. The files live in ``/var/run``
        (tmpfs), so they are gone after a reboot and never reach the pool.
        """
        entries = record.get('certificates') or []
        if not entries:
            await self.middleware.run_in_thread(self._remove_certificate_files, record['name'])
            return {'hash': None, 'changed': [], 'restart': False}
        runtime_owner = self._declared_runtime_owner(record.get('environment'))
        rendered = {}
        changed = []
        for index, entry in enumerate(entries):
            certificate = await self.middleware.call(
                'certificate.query', [['id', '=', entry['id']]],
            )
            certificate = self._certificate_reference(entry, certificate[0] if certificate else None)
            try:
                files = app_certificates.rendered_files(certificate)
            except app_certificates.CertificateMountError as error:
                raise CallError(
                    f'Certificate {entry["name"]!r} cannot be mounted: {error}'
                ) from error
            directory = app_certificates.entry_directory(record['name'], index)
            if await self.middleware.run_in_thread(
                self._write_certificate_files, directory, files,
                app_certificates.entry_owner(entry, runtime_owner),
            ):
                changed.append(index)
            rendered[str(index)] = files
        # The parent is root-only, so no host user can traverse to another
        # application's keys even when an entry is owned by an unprivileged uid.
        await self.middleware.run_in_thread(
            os.chmod, app_certificates.certificates_root(record['name']), 0o700,
        )
        # Entries left over from a shorter list (an edit removed one) are not mounted
        # by the container that is about to be created, and their keys must not linger.
        await self.middleware.run_in_thread(
            self._prune_certificate_directories, record['name'], len(entries),
        )
        return {
            'hash': app_certificates.content_hash(rendered),
            'changed': changed,
            'restart': any(entries[index].get('restart_on_change', True) for index in changed),
        }

    async def _clear_certificate_alerts(self, application, classes=CERTIFICATE_ALERT_CLASSES):
        """Drop the certificate alerts an application no longer deserves.

        the internal development record: both are one-shot alerts, so nothing clears them unless
        the path that proves them stale does: a render that succeeded, a start or a
        restart that went through, a replaced container, a removed application.
        """
        for klass in classes:
            try:
                await self.middleware.call('alert.oneshot_delete', klass, application)
            except Exception:  # noqa: BLE001 -- an alert must not fail a lifecycle job
                self.logger.warning(
                    'Unable to clear %s for application %r', klass, application, exc_info=True,
                )

    def _prune_certificate_directories(self, application, count):
        root = app_certificates.certificates_root(application)
        try:
            names = os.listdir(root)
        except FileNotFoundError:
            return
        for name in names:
            if not name.isdigit() or int(name) >= count:
                path = os.path.join(root, name)
                with contextlib.suppress(FileNotFoundError):
                    shutil.rmtree(path) if os.path.isdir(path) else os.unlink(path)

    @lock('applications_lifecycle_internal')
    @private
    @job(lock='applications_lifecycle')
    async def reconcile_certificates(self, job, certificate_ids=None):
        """Re-render mounted certificates and restart the applications that asked for it.

        the internal development record: called after a renewal or a change in the certificate
        store, never on the daily ``service.start ssl`` (which runs at every start and
        would restart every application daily while still missing renewals). One pass
        renders each application once and restarts it at most once, and only when a
        rewritten entry carries ``restart_on_change``.

        Start and boot render too but never restart: this is the only path that does.

        The pass holds the lifecycle locks, as every job that renders does. An edit or a
        catalog update renders its replacement's directories seconds before it commits
        the record; a pass reading the record in between would write the previous list
        over them and prune a directory the new container mounts. For the same reason the
        restart is done here and not through ``applications.restart``, which takes the
        same locks. The certificate path never waits for this job.
        """
        config = await self.config()
        if not config['pool'] or not config['runtime_ready']:
            # Nothing is mounted while the runtime is down; boot renders from scratch.
            return {'rendered': [], 'restarted': [], 'skipped': 'runtime_not_ready'}
        records, _ = self._read_records(config)
        wanted = set(certificate_ids) if certificate_ids else None
        rendered = []
        restarted = []
        for record in records:
            entries = record.get('certificates') or []
            if not entries:
                continue
            if wanted is not None and not any(entry['id'] in wanted for entry in entries):
                continue
            try:
                result = await self.render_certificates(record)
            except Exception as error:  # noqa: BLE001 -- one application must not stop the pass
                self.logger.warning(
                    'Failed to render certificates for application %r', record['name'],
                    exc_info=True,
                )
                await self.middleware.call(
                    'alert.oneshot_create', 'ApplicationsCertificateRenderFailed',
                    {'application': record['name'], 'error': str(error)},
                )
                continue
            await self._clear_certificate_alerts(
                record['name'], ('ApplicationsCertificateRenderFailed',),
            )
            if not result['changed']:
                continue
            rendered.append(record['name'])
            if not result['restart']:
                continue
            try:
                # A stopped application keeps only the fresh files; it reads them when started.
                owned = await self._inspect_owned_container(config, record)
                if owned is None or not (owned[0].get('State') or {}).get('Running'):
                    continue
                # As applications.restart does. No health wait: _wait_healthy reads the
                # restart count, which only means something for a container just created.
                await self._prepare_lan_network(config, record)
                await self._complete_ignoring_cancellation(
                    self._podman(config, 'restart', owned[1])
                )
                restarted.append(record['name'])
                await self._clear_certificate_alerts(
                    record['name'], ('ApplicationsCertificateRestartFailed',),
                )
            except Exception as error:  # noqa: BLE001
                # One alert, no retry: the files are already current, so a later pass
                # sees no change and does not try again.
                self.logger.warning(
                    'Failed to restart application %r after a certificate change',
                    record['name'], exc_info=True,
                )
                await self.middleware.call(
                    'alert.oneshot_create', 'ApplicationsCertificateRestartFailed',
                    {'application': record['name'], 'error': str(error)},
                )
        return {'rendered': rendered, 'restarted': restarted}

    @private
    async def certificates_in_use(self, certificate_id):
        """The applications that mount this certificate, by name.

        the internal development record: ``check_dependencies`` follows database foreign keys and
        cannot see records on the Applications pool, so the certificate delete asks here.
        """
        config = await self.config()
        if not config['pool']:
            return []
        # A configured pool that is exported, locked or otherwise not mounted would read as
        # "no application mounts it" and let the delete through, so it is refused instead.
        records_path = Path(application_paths(config['pool'])['records'])
        if not records_path.is_dir():
            raise CallError(
                f'The Applications pool {config["pool"]!r} is not available, so whether an '
                'application mounts this certificate cannot be determined. Import the pool, or '
                'unset the Applications pool, before deleting the certificate.',
                errno.EBUSY,
            )
        try:
            records, _ = self._read_records(config)
        except Exception:
            self.logger.warning('Unable to read Applications records', exc_info=True)
            raise CallError(
                'Unable to determine whether an application mounts this certificate because '
                'the Applications records are unreadable; resolve that before deleting it.',
                errno.EBUSY,
            )
        return sorted(
            record['name'] for record in records
            if any(entry['id'] == certificate_id for entry in (record.get('certificates') or []))
        )

    async def _prepare_volumes(self, config, data, created):
        paths = application_paths(config['pool'])
        owner = f'applications:{data["name"]}'
        runtime_owner = self._declared_runtime_owner(data.get('environment'))
        volumes = []
        owned = [volume for volume in data['volumes'] if volume['dataset'] is None]
        if owned:
            await self._ensure_owned_dataset(
                f'{paths["data_dataset"]}/{data["name"]}', owner, created
            )

        for volume in data['volumes']:
            if volume['dataset'] is None:
                dataset = f'{paths["data_dataset"]}/{data["name"]}/{volume["name"]}'
                await self._ensure_owned_dataset(
                    dataset, owner, created, runtime_owner=runtime_owner
                )
                source = f'/mnt/{dataset}'
                is_owned = True
            else:
                dataset = volume['dataset']
                components = dataset.split('/')
                if len(components) > 1 and components[1] in {
                    'applications', 'bastille', 'iocage'
                }:
                    raise CallError(
                        f'External dataset {dataset!r} overlaps a managed jail or Applications hierarchy.'
                    )
                source = await self._dataset_mountpoint(dataset)
                if not source:
                    raise CallError(f'External dataset {dataset!r} is not mounted and available.')
                if (
                    not source.startswith('/mnt/') or
                    ':' in source or
                    os.path.normpath(source) != source
                ):
                    raise CallError(
                        f'External dataset {dataset!r} has an unsafe mountpoint {source!r}.'
                    )
                is_owned = False

            volumes.append({
                'name': volume['name'],
                'target': volume['target'],
                'dataset': dataset,
                'source': source,
                'owned': is_owned,
                'read_only': volume['read_only'],
            })
        return volumes

    @staticmethod
    async def _probe_http_health(healthcheck, timeout):
        request_timeout = aiohttp.ClientTimeout(total=max(0.05, min(5.0, timeout)))
        host = healthcheck.get('probe_host') or '127.0.0.1'
        port = healthcheck.get('probe_port') or healthcheck['host_port']
        url = f'{healthcheck["scheme"]}://{host}:{port}{healthcheck["path"]}'
        try:
            async with (
                aiohttp.ClientSession(
                    timeout=request_timeout,
                    trust_env=False,
                    headers={'User-Agent': 'FreeCORE-Applications-health/1'},
                ) as session,
                session.get(url, allow_redirects=False) as response,
            ):
                if 200 <= response.status < 400:
                    return True, f'HTTP status {response.status}'
                return False, f'HTTP status {response.status}'
        except asyncio.TimeoutError:
            return False, 'HTTP probe timed out'
        except aiohttp.ClientError:
            return False, 'HTTP endpoint is not reachable'

    async def _settled_inspection(self, config, container, inspection, redactions=()):
        """The inspection an install may commit: nothing has crashed under s6 meanwhile."""
        crashed = await self._supervised_service_crash(config, container, redactions)
        if crashed:
            raise CallError(f'Application service crashed during startup: {crashed}')
        return inspection

    async def _supervised_service_crash(self, config, container, redactions=()):
        """The s6 crash line from the container log, with the log tail, or None.

        the internal development record: navidrome shipped a default that made it exit on
        start; s6 restarted it every five seconds and podman reported a running
        container.  The line s6 prints is the only place the death is visible.
        """
        try:
            cp = await self._podman(
                config, 'logs', '--tail', str(STARTUP_FAILURE_LOG_LINES), container,
                check=False, redactions=redactions,
            )
        except Exception:  # noqa: BLE001
            return None
        output = f'{cp.stdout or ""}{cp.stderr or ""}'
        match = None
        for match in S6_CRASH_LINE.finditer(output):
            pass
        if match is None:
            return None
        excerpt = output.strip()[-STARTUP_FAILURE_LOG_BYTES:]
        for secret in redactions:
            if secret:
                excerpt = excerpt.replace(secret, '********')
        return f"service {match.group(1)!r} crashed under s6. Last output:\n{excerpt}"

    async def _startup_failure_detail(self, config, container, state=None, redactions=()):
        """Explain a startup failure while the container still exists to explain it.

        the internal development record: rollback removes the transaction container, and the
        record is only committed after this returns, so `applications.logs` can never
        reach either. This is the one moment the operator's actual traceback exists.

        `State.Error` is empty for an ordinary non-zero exit of the application
        process -- the common case -- which is why the failure read "unknown error"
        for a deterministic SQLite permission fault.
        """
        state = state or {}
        parts = []
        reason = (state.get('Error') or '').strip()
        if reason:
            parts.append(reason)
        exit_code = state.get('ExitCode')
        if isinstance(exit_code, int) and exit_code:
            parts.append(f'exit status {exit_code}')
        detail = '; '.join(parts) or 'unknown error'

        excerpt = ''
        try:
            cp = await self._podman(
                config, 'logs', '--tail', str(STARTUP_FAILURE_LOG_LINES), container,
                check=False, redactions=redactions,
            )
            excerpt = f'{cp.stdout or ""}{cp.stderr or ""}'.strip()[-STARTUP_FAILURE_LOG_BYTES:]
        except Exception:  # noqa: BLE001
            # Collecting the explanation must never replace the failure it explains.
            self.middleware.logger.warning(
                'Unable to retain startup output for application container %r',
                container, exc_info=True,
            )
            excerpt = ''

        for secret in redactions:
            if secret:
                excerpt = excerpt.replace(secret, '********')

        if excerpt:
            return f'{detail}. Last output before rollback:\n{excerpt}'
        return detail

    @staticmethod
    def _timestamp(value):
        """podman's RFC 3339 timestamps carry nanoseconds; fromisoformat takes six digits."""
        if not isinstance(value, str) or value.startswith('0001-'):
            return None
        trimmed = re.sub(r'(\.\d{6})\d+', r'\1', value.replace('Z', '+00:00'))
        try:
            parsed = datetime.fromisoformat(trimmed)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    @classmethod
    def _classify_state(cls, record, inspection, now=None):
        """What the container's state means for the record (the internal development record).

        podman counts the restarts its policy performed (`RestartCount`, reset by
        an explicit start, kept across a user stop).  A count with the container
        between restarts, or running again since only minutes ago, is a crash
        loop and reads RESTARTING; a user-stopped container keeps reading EXITED.
        """
        state = inspection.get('State') or {}
        status = str(state.get('Status') or 'UNKNOWN').upper()
        running = bool(state.get('Running'))
        restarts = inspection.get('RestartCount')
        restarts = restarts if isinstance(restarts, int) and restarts > 0 else 0
        exit_code = state.get('ExitCode') if not running and isinstance(state.get('ExitCode'), int) else None
        error = state.get('Error') or None
        if (
            restarts and status in ('RUNNING', 'STOPPED') and
            record.get('restart_policy') in ('always', 'on-failure')
        ):
            started = cls._timestamp(state.get('StartedAt'))
            now = now or datetime.now(timezone.utc)
            if status == 'STOPPED' or started is None or (now - started).total_seconds() <= RESTART_WINDOW_SECONDS:
                status = 'RESTARTING'
                detail = f'exit status {exit_code}; ' if exit_code else ''
                error = (
                    f'The container restarted {restarts} time{"s" if restarts != 1 else ""} '
                    f'({detail}restart policy {record.get("restart_policy")}); see the application log.'
                )
        return {'status': status, 'running': running, 'restarts': restarts, 'exit_code': exit_code, 'error': error}

    async def _wait_healthy(
        self, config, container, timeout, healthcheck=None, redactions=(),
    ):
        deadline = asyncio.get_running_loop().time() + timeout
        last_probe = None
        settled = timeout == 0
        while True:
            inspection = await self._inspect_container(config, container)
            state = inspection.get('State') or {}
            if not state.get('Running'):
                raise CallError(
                    'Application container stopped during startup: '
                    + await self._startup_failure_detail(
                        config, container, state, redactions
                    )
                )
            restarts = inspection.get('RestartCount')
            if isinstance(restarts, int) and restarts > 0:
                # the internal development record: podman's restart policy hid the death.
                raise CallError(
                    f'Application container restarted {restarts} time{"s" if restarts != 1 else ""} '
                    'during startup: '
                    + await self._startup_failure_detail(config, container, state, redactions)
                )
            if healthcheck is None:
                if settled:
                    return await self._settled_inspection(config, container, inspection, redactions)
                # No health check to consult: give a service that dies on its
                # first seconds the chance to do so where the install can see it.
                settled = True
                await asyncio.sleep(min(STARTUP_SETTLE_SECONDS, timeout))
                continue

            health = state.get('Health') or {}
            status = (health.get('Status') or health.get('status') or '').lower()
            if status == 'unhealthy':
                raise CallError(
                    'Application container reported an unhealthy state: '
                    + await self._startup_failure_detail(
                        config, container, state, redactions
                    )
                )

            remaining = max(0.0, deadline - asyncio.get_running_loop().time())
            probe_timeout = 0.05 if timeout == 0 else max(0.05, min(5.0, remaining))
            healthy, last_probe = await self._probe_http_health(healthcheck, probe_timeout)
            if healthy:
                return await self._settled_inspection(config, container, inspection, redactions)
            remaining = deadline - asyncio.get_running_loop().time()
            if timeout == 0 or remaining <= 0:
                raise CallError(
                    'Timed out waiting for declared application HTTP health check '
                    f'({last_probe}). '
                    + await self._startup_failure_detail(
                        config, container, state, redactions
                    )
                )
            await asyncio.sleep(min(2, remaining))

    @staticmethod
    def _validate_owned_container_inspection(
        record, inspection, transaction_id=None, require_record_identity=True,
    ):
        container_id = inspection.get('Id') if isinstance(inspection, dict) else None
        raw_config = inspection.get('Config') if isinstance(inspection, dict) else None
        labels = raw_config.get('Labels') if isinstance(raw_config, dict) else None
        if not isinstance(labels, dict):
            labels = inspection.get('Labels') if isinstance(inspection, dict) else None
        if (
            not isinstance(container_id, str) or
            not re.fullmatch(CONTAINER_ID, container_id) or
            not isinstance(labels, dict) or
            labels.get(MANAGED_LABEL) != 'true' or
            labels.get(APPLICATION_LABEL) != record['name'] or
            transaction_id is not None and labels.get(TRANSACTION_LABEL) != transaction_id or
            require_record_identity and container_id != record.get('container_id')
        ):
            raise CallError(
                f'Refusing to mutate container {record["container_name"]!r}; '
                'its immutable identity or Applications ownership labels do not match.'
            )
        return container_id

    async def _inspect_owned_container(
        self, config, record, container=None, transaction_id=None,
        require_record_identity=True,
    ):
        container = container or record['container_id']
        if not await self._container_exists(config, container):
            return None
        inspection = await self._inspect_container(config, container)
        container_id = self._validate_owned_container_inspection(
            record, inspection, transaction_id, require_record_identity
        )
        return inspection, container_id

    async def _inspect_managed_containers(self, config, records):
        """Every record's container in two podman calls instead of two per record.

        the internal development record: `podman container exists` and `podman container
        inspect` ran once per record, and each podman start-up lists every layer
        dataset under the graphroot before it does anything, so a page of 23
        applications cost 46 invocations and 20 seconds.  One `ps` gives the
        definitive set of containers, one `inspect` reads them all, and each
        record is then validated exactly as the single-record path validates it.

        Returns {record name: (inspection, container id) | None | CallError}:
        None is an absent container; a CallError is a container that exists but
        is not the record's (identity or ownership labels do not match).  When
        the batched inspect cannot be trusted (a container removed between the
        two calls) the single-record path answers for every record instead.
        """
        result = {record['name']: None for record in records}
        wanted = {}
        for record in records:
            container = record.get('container_id')
            if isinstance(container, str) and re.fullmatch(CONTAINER_ID, container):
                wanted.setdefault(container, []).append(record)
            else:
                # Not something a batched inspect can name; the single-record path
                # keeps answering for it exactly as before.
                try:
                    result[record['name']] = await self._inspect_owned_container(config, record)
                except CallError as error:
                    result[record['name']] = error
        if not wanted:
            return result

        try:
            listing = await self._podman(
                config, 'ps', '--all', '--no-trunc', '--format', 'json', check=False,
            )
            if listing.returncode:
                raise CallError(f'Podman ps failed with exit status {listing.returncode}.')
            present = {
                entry.get('Id') for entry in json.loads(listing.stdout or '[]')
                if isinstance(entry, dict)
            }
            inspections = {}
            targets = [container for container in wanted if container in present]
            if targets:
                cp = await self._podman(config, 'container', 'inspect', *targets, check=False)
                if cp.returncode:
                    raise CallError(f'Podman inspect failed with exit status {cp.returncode}.')
                for inspection in json.loads(cp.stdout or '[]'):
                    if isinstance(inspection, dict) and inspection.get('Id') in wanted:
                        inspections[inspection['Id']] = inspection
            if set(inspections) != set(targets):
                raise CallError('Podman inspected a different set of containers than it listed.')
        except (CallError, TypeError, ValueError):
            self.logger.warning(
                'Batched container inspection failed; inspecting managed containers one by one',
                exc_info=True,
            )
            for owners in wanted.values():
                for record in owners:
                    try:
                        result[record['name']] = await self._inspect_owned_container(config, record)
                    except CallError as error:
                        result[record['name']] = error
            return result

        for container, owners in wanted.items():
            inspection = inspections.get(container)
            if inspection is None:
                continue
            for record in owners:
                try:
                    result[record['name']] = (
                        inspection, self._validate_owned_container_inspection(record, inspection)
                    )
                except CallError as error:
                    result[record['name']] = error
        return result

    async def _transaction_container(
        self, config, record, transaction_id, container_id=None,
    ):
        if container_id is not None:
            if not re.fullmatch(CONTAINER_ID, container_id):
                raise CallError('Attempted container identity is invalid.')
            candidates = [container_id] if await self._container_exists(
                config, container_id
            ) else []
        else:
            cp = await self._podman(
                config,
                'container',
                'ls',
                '--all',
                '--no-trunc',
                '--quiet',
                '--filter',
                f'label={TRANSACTION_LABEL}={transaction_id}',
            )
            candidates = [line.strip() for line in cp.stdout.splitlines() if line.strip()]
            if (
                len(candidates) != len(set(candidates)) or
                any(not re.fullmatch(CONTAINER_ID, candidate) for candidate in candidates)
            ):
                raise CallError('Podman returned invalid transaction container identities.')

        owned = []
        for candidate in candidates:
            if not await self._container_exists(config, candidate):
                continue
            inspection = await self._inspect_container(config, candidate)
            inspected_id = self._validate_owned_container_inspection(
                record, inspection, transaction_id, require_record_identity=False,
            )
            if inspected_id != candidate:
                raise CallError('Transaction container identity changed during inspection.')
            owned.append((inspection, inspected_id))
        if len(owned) > 1:
            raise CallError('Multiple containers claim one Applications transaction identity.')
        return owned[0] if owned else None

    async def _remove_transaction_container(
        self, config, record, transaction_id, container_id=None,
    ):
        owned = await self._transaction_container(
            config, record, transaction_id, container_id,
        )
        if owned is not None:
            await self._podman(config, 'rm', '--force', owned[1])

    async def _remove_owned_container(
        self, config, record, container=None, transaction_id=None,
    ):
        owned = await self._inspect_owned_container(
            config, record, container, transaction_id
        )
        if owned is not None:
            await self._podman(config, 'rm', '--force', owned[1])

    async def _require_owned_container(self, config, record):
        owned = await self._inspect_owned_container(config, record)
        if owned is None:
            raise CallError(
                f'Managed container {record["container_name"]!r} is unavailable.'
            )
        return owned

    async def _refresh_restart_on_boot(self, config, force=False):
        records, _ = self._read_records(config)
        enabled = any(record.get('restart_policy') == 'always' for record in records)
        if force or enabled != config['restart_on_boot']:
            await self.middleware.call(
                'datastore.update', 'services.applications', config['id'],
                {'restart_on_boot': enabled}, {'prefix': 'app_'}
            )
            config['restart_on_boot'] = enabled
            await self.middleware.call('etc.generate', 'rc')

    @private
    @job(lock='applications_lifecycle')
    async def install_catalog(self, job, data, catalog, origin=None):
        return await self._install_impl(job, data, catalog, origin)

    @private
    async def podman(self, *arguments):
        """Run podman inside the Applications runtime for another plugin.

        the internal development record: the converter's migration hop needs the same
        storage and network configuration every managed container gets. A trailing
        boolean ``False`` argument turns the non-zero-exit CallError off; the
        completed process is returned as plain data either way.
        """
        config = await self._require_config()
        arguments = list(arguments)
        check = True
        if arguments and isinstance(arguments[-1], bool):
            check = arguments.pop()
        cp = await self._podman(config, *arguments, check=check)
        return {'returncode': cp.returncode, 'stdout': cp.stdout, 'stderr': cp.stderr}

    @private
    async def host_port_free(self, port, protocol):
        """Whether a host port is free for a new application (the internal development record).

        The same three answers `_validate_install` gives: not assigned to a managed
        application, not reserved for appliance management, not bound on the host.
        """
        config = await self._require_config()
        records, _ = self._read_records(config)
        key = (port, protocol)
        if any(
            (item['host_port'], item['protocol']) == key
            for record in records for item in record.get('ports', [])
        ):
            return False
        if key in await self._reserved_management_ports():
            return False
        return bool(await self.middleware.run_in_thread(self._port_available, port, protocol))

    @private
    async def catalog_record(self, name):
        config = await self._require_config()
        return copy.deepcopy(self._get_record(config, name))

    @private
    @job(lock='applications_lifecycle')
    async def install_with_origin(self, job, data, origin):
        """The converter's install (the internal development record): a bound payload plus its origin."""
        if not isinstance(origin, dict) or origin.get('kind') not in ORIGIN_KINDS:
            raise CallError('Application origin is invalid.')
        return await self._install_impl(job, data, None, origin)

    @private
    async def prepare_owned_volume(self, name, volume, runtime_owner=None):
        """Create (or accept) the owned dataset an install will bind for `volume`.

        the internal development record: the converter fills an application's storage before
        the application exists. `_prepare_volumes` accepts an owned dataset that
        already exists with the right stamp and does not restamp it, so staging
        into exactly this dataset is the supported way to hand data to an install.
        Returns the dataset, its mountpoint and the datasets this call created.
        """
        config = await self._require_config()
        paths = application_paths(config['pool'])
        owner = f'applications:{name}'
        created = []
        dataset = f'{paths["data_dataset"]}/{name}/{volume}'
        try:
            await self._ensure_owned_dataset(f'{paths["data_dataset"]}/{name}', owner, created)
            await self._ensure_owned_dataset(
                dataset, owner, created,
                runtime_owner=tuple(runtime_owner) if runtime_owner else None,
            )
        except BaseException:
            await self._complete_ignoring_cancellation(
                self._delete_attempted_owned_datasets(
                    created, {item: owner for item in created}
                )
            )
            raise
        return {'dataset': dataset, 'mountpoint': f'/mnt/{dataset}', 'created': created}

    @private
    async def discard_owned_datasets(self, name, datasets):
        """Remove datasets `prepare_owned_volume` created for an install that never happened."""
        owner = f'applications:{name}'
        return await self._delete_attempted_owned_datasets(
            list(datasets), {item: owner for item in datasets}
        )

    @lock('applications_lifecycle_internal')
    @accepts(Dict(
        'applications_reconfigure',
        Str('name', required=True, validators=[Match(APPLICATION_NAME)]),
        # The installed contract's hash as the form saw it (None for a record
        # without catalog provenance); a stale form is refused, not applied.
        Str('compose_sha256', default=None, null=True, validators=[Match(r'^[0-9a-f]{64}$')]),
        List('ports', items=[Dict(
            'port',
            # the internal development record: null keeps the port on the managed bridge.
            Int('host_port', required=True, null=True, validators=[Range(min=1, max=65535)]),
            Int('container_port', required=True, validators=[Range(min=1, max=65535)]),
            Str('protocol', required=True, enum=['tcp', 'udp']),
        )], default=[]),
        List('environment', items=[Dict(
            'environment',
            Str('name', required=True, validators=[Match(ENVIRONMENT_NAME)]),
            # null keeps the installed value: the page never sees values.
            Str(
                'value', default=None, null=True, private=True, max_length=65536,
                validators=[Match(ENVIRONMENT_VALUE)],
            ),
        )], default=[]),
        List('volumes', items=[Dict(
            'volume',
            Str('name', required=True, validators=[Match(APPLICATION_NAME)]),
            Str('dataset', default=None, null=True, validators=[Match(DATASET_NAME)]),
        )], default=[]),
        # the internal development record: null keeps the installed labels; a list -- the empty one
        # included -- replaces them. The edit form always sends its list.
        List('labels', items=[Dict(
            'label',
            Str('name', required=True, validators=[Match(LABEL_NAME)]),
            Str('value', required=True, validators=[Match(LABEL_VALUE)]),
        )], default=None, null=True),
        # the internal development record: null keeps the mounted certificates, a list replaces them.
        List('certificates', items=[Dict(
            'certificate',
            Int('id', required=True),
            Str('name', required=True, empty=False),
            Str('fingerprint', required=True, empty=False),
            Str('target', required=True, empty=False),
            Bool('restart_on_change', default=True),
            Int('uid', default=None, null=True, validators=[Range(min=0)]),
            Int('gid', default=None, null=True, validators=[Range(min=0)]),
        )], default=None, null=True),
        Str('restart_policy', enum=['no', 'on-failure', 'always'], default='always'),
        # null keeps the installed attachment: the page need not echo it back.
        Dict(
            'network',
            Str('mode', enum=['managed', 'lan'], default='managed'),
            Str('interface', default=None, null=True),
            Str('address', default=None, null=True),
            Str('gateway', default=None, null=True),
            Bool('managed_access', default=False),
            null=True, default=None,
        ),
        Int('health_timeout', default=60, validators=[Range(min=0, max=300)]),
    ))
    @job(lock='applications_lifecycle')
    async def reconfigure(self, job, data):
        """Change an installed application's host ports, environment values,
        storage mappings or restart policy in place (the internal development record).

        The new choices bind to the record's own declarations -- the same
        container ports, environment names and volumes it was installed with --
        and the container is replaced through the same rollback-protected path
        a catalog update uses, with the image it already has.  A volume moved
        from app-owned to external storage leaves the owned dataset in place;
        one moved to app-owned storage reattaches an existing owned dataset of
        that name or gets a new empty one.  The result names all three.
        """
        config = await self._require_config()
        current = self._get_record(config, data['name'])
        if data.get('certificates') is not None:
            # the internal development record: refused here, before the running container is touched.
            data = {**data, 'certificates': await self._bind_requested_certificates(
                current, data['certificates'], 'applications_reconfigure.certificates',
            )}
        try:
            prepare, fields, changes = bind_reconfigure(current, data)
        except ReconfigureError as error:
            raise CallError(str(error)) from error
        result = {
            'changes': changes,
            'kept_datasets': [
                item['kept_dataset'] for item in changes['volumes'] if item.get('kept_dataset')
            ],
            'reattached_datasets': [],
            'created_datasets': [],
        }
        if not anything_changed(changes):
            result['application'] = await self.middleware.call(
                'applications.query', [('name', '=', current['name'])], {'get': True}
            )
            return result

        pin_field = (
            'managed_address' if fields['network'].get('managed_access')
            else 'bridge_address' if fields['network']['mode'] == 'managed' else None
        )
        if pin_field and not fields['network'].get(pin_field):
            allocation_records, _ = self._read_records(config)
            fields['network'][pin_field] = self._allocate_managed_leg_address(
                config, allocation_records, current['name'],
            )
        await self._validate_reconfigure(config, current, fields['ports'], fields['network'])

        owner = f'applications:{current["name"]}'
        created_datasets = []
        job.set_progress(10, 'Preparing application storage')
        try:
            volumes = await self._prepare_volumes(config, prepare, created_datasets)
            if created_datasets and self._declared_runtime_owner(prepare.get('environment')) is None:
                # the internal development record: a volume an edit adds gets the image's own runtime user too.
                # Best effort: the edit does not depend on it, so an unreadable image only skips it.
                try:
                    image_info = await self._inspect_image(
                        config, current['image'], allow_linux=current.get('image_os') == 'linux',
                    )
                except Exception:  # noqa: BLE001
                    self.logger.warning('Unable to read the runtime user of %r', current['image'], exc_info=True)
                    image_info = {}
                image_owner = self._image_runtime_owner(image_info.get('env'))
                if image_owner is not None:
                    await self._give_new_volumes_to(volumes, created_datasets, image_owner)
        except BaseException:
            await self._complete_ignoring_cancellation(self._delete_attempted_owned_datasets(
                created_datasets, {dataset: owner for dataset in created_datasets},
            ))
            raise
        moved_to_owned = {
            item['name'] for item in changes['volumes'] if item['to'] is None
        }
        result['created_datasets'] = list(created_datasets)
        result['reattached_datasets'] = [
            volume['dataset'] for volume in volumes
            if volume['owned'] and volume['name'] in moved_to_owned
            and volume['dataset'] not in created_datasets
        ]

        new_record = copy.deepcopy(current)
        new_record.update({
            'container_id': None,
            'ports': copy.deepcopy(fields['ports']),
            'environment': copy.deepcopy(fields['environment']),
            'volumes': volumes,
            'labels': copy.deepcopy(fields['labels']),
            'certificates': copy.deepcopy(fields['certificates']),
            'restart_policy': fields['restart_policy'],
            'portal': copy.deepcopy(fields['portal']),
            'healthcheck': copy.deepcopy(fields['healthcheck']),
            'updated_at': datetime.now(timezone.utc).isoformat(),
        })
        if new_record.get('schema', 3) < 3:
            # the internal development record semantics: pre-3 records are native
            # images of catalog origin; schema 4 carries those fields.
            new_record.setdefault('image_os', 'freebsd')
            new_record.setdefault('origin', None)
        new_record['schema'] = 4
        new_record['network'] = copy.deepcopy(fields['network'])
        new_record = self._validate_record(
            config, new_record, current['name'], allow_unbound_container=True,
        )
        try:
            await self._replace_container(
                job, config, current, new_record, data['health_timeout'], 'reconfigure',
            )
        except BaseException:
            await self._complete_ignoring_cancellation(self._delete_attempted_owned_datasets(
                created_datasets, {dataset: owner for dataset in created_datasets},
            ))
            raise

        job.set_progress(100, 'Application reconfiguration complete')
        result['application'] = await self._complete_ignoring_cancellation(
            self.middleware.call(
                'applications.query', [('name', '=', current['name'])], {'get': True}
            )
        )
        return result

    async def _validate_reconfigure(self, config, current, ports, network=None):
        """The install-time port rules, minus the ports this application already holds."""
        verrors = ValidationErrors()
        records, _ = self._read_records(config)
        if (network or {}).get('mode') == 'lan':
            # the internal development record: a LAN attachment publishes nothing; the
            # install-time attachment rules apply instead of the port rules.
            await self._validate_lan_network(
                verrors, 'applications_reconfigure.network', config, network, records,
                current_name=current['name'],
            )
            verrors.check()
            return
        # the internal development record: a port kept on the managed bridge holds no host port.
        used_ports = {
            (port['host_port'], port['protocol'])
            for record in records
            if record['name'] != current['name'] and
            (record.get('network') or {}).get('mode') != 'lan'
            for port in record.get('ports', [])
            if port['host_port'] is not None
        }
        held_ports = {(port['host_port'], port['protocol']) for port in current.get('ports', [])}
        requested = [(port['host_port'], port['protocol']) for port in ports]
        published = [key for key in requested if key[0] is not None]
        if len(published) != len(set(published)):
            verrors.add('applications_reconfigure.ports', 'Host port/protocol pairs must be unique.')
        reserved = await self._reserved_management_ports()
        for index, key in enumerate(requested):
            if key[0] is None:
                continue
            if key in used_ports:
                verrors.add(
                    f'applications_reconfigure.ports.{index}.host_port',
                    'Host port is already assigned to a managed application.',
                )
            elif key in reserved:
                verrors.add(
                    f'applications_reconfigure.ports.{index}.host_port',
                    'Host port is reserved for appliance management.',
                )
            elif key not in held_ports and not await self.middleware.run_in_thread(
                self._port_available, *key
            ):
                verrors.add(
                    f'applications_reconfigure.ports.{index}.host_port',
                    'Host port is already in use.',
                )
        verrors.check()

    # -- app-owned datasets: what exists, what is mapped, what is nobody's -----
    # the internal development record.  One `zfs list` over the data store answers for
    # every application; the page asks before a Remove, before an install under
    # a name that has been used, and for the orphan list.

    async def _list_owned_datasets(self, root):
        """``[(dataset, used bytes, mountpoint, managedby)]`` two levels under ``root``."""
        try:
            cp = await run(
                ['zfs', 'list', '-H', '-p', '-r', '-d', '2', '-t', 'filesystem',
                 '-o', f'name,used,mountpoint,{MANAGED_PROPERTY}', root],
                check=False, encoding='utf8',
            )
        except OSError:
            return []
        if cp.returncode:
            return []
        rows = []
        for line in (cp.stdout or '').splitlines():
            parts = line.split('\t')
            if len(parts) != 4 or parts[0] == root:
                continue
            try:
                used = int(parts[1])
            except ValueError:
                used = 0
            rows.append((parts[0], used, parts[2], parts[3] if parts[3] != '-' else None))
        return rows

    def _owned_data_report(self, paths, records, rows):
        by_application = {}
        mapped = {
            volume['dataset']: (record['name'], volume['name'])
            for record in records for volume in record.get('volumes', [])
            if volume.get('owned') and isinstance(volume.get('dataset'), str)
        }
        names = {record['name'] for record in records}
        prefix = paths['data_dataset'] + '/'
        for dataset, used, mountpoint, managedby in rows:
            relative = dataset[len(prefix):] if dataset.startswith(prefix) else None
            if not relative:
                continue
            application, _, volume_part = relative.partition('/')
            entry = {
                'dataset': dataset,
                'application': application,
                'volume': mapped[dataset][1] if dataset in mapped else None,
                'parent': not volume_part,
                'mountpoint': mountpoint,
                'used': used,
                'owner': managedby,
                # Nobody's: no record of that name, or a volume no record maps.
                'orphan': application not in names or (bool(volume_part) and dataset not in mapped),
            }
            by_application.setdefault(application, []).append(entry)
        return by_application

    @staticmethod
    def _orphan_bytes(orphans):
        """Bytes the list stands for: a parent's `used` already includes its
        children, so a parent counts only when none of its children is listed."""
        with_children = {item['dataset'].rsplit('/', 1)[0] for item in orphans if not item['parent']}
        return sum(
            item['used'] for item in orphans
            if not item['parent'] or item['dataset'] not in with_children
        )

    @accepts(Str('name', default=None, null=True, validators=[Match(APPLICATION_NAME)]))
    async def owned_datasets(self, name):
        """App-owned datasets under the store, by application name, with what
        maps them (the internal development record).  ``name`` limits the answer to one
        application, which need not exist any more -- that is what a Remove
        keeps and what an install under the same name reattaches.
        """
        config = await self._require_config()
        paths = application_paths(config['pool'])
        records, _ = self._read_records(config)
        rows = await self._list_owned_datasets(paths['data_dataset'])
        report = self._owned_data_report(paths, records, rows)
        if name is not None:
            return report.get(name, [])
        return [entry for entries in report.values() for entry in entries]

    @accepts()
    async def orphaned_data(self):
        """App-owned datasets no installed application maps (the internal development record)."""
        return [entry for entry in await self.owned_datasets(None) if entry['orphan']]

    @accepts(Dict(
        'applications_install',
        Str('name', required=True, validators=[Match(APPLICATION_NAME)]),
        Str('image', required=True, empty=False),
        Str('image_os', enum=['freebsd', 'linux'], default='freebsd'),
        List('ports', items=[Dict(
            'port',
            # the internal development record: null keeps the port on the managed bridge.
            Int('host_port', required=True, null=True, validators=[Range(min=1, max=65535)]),
            Int('container_port', required=True, validators=[Range(min=1, max=65535)]),
            Str('protocol', required=True, enum=['tcp', 'udp']),
        )], default=[]),
        List('environment', items=[Dict(
            'environment',
            Str('name', required=True, validators=[Match(ENVIRONMENT_NAME)]),
            Str(
                'value', required=True, private=True, max_length=65536,
                validators=[Match(ENVIRONMENT_VALUE)],
            ),
        )], default=[]),
        List('volumes', items=[Dict(
            'volume',
            Str('name', required=True, validators=[Match(APPLICATION_NAME)]),
            Str('target', required=True, empty=False),
            Str('dataset', default=None, null=True, validators=[Match(DATASET_NAME)]),
            Bool('read_only', default=False),
        )], default=[]),
        List('annotations', items=[Dict(
            'annotation',
            Str('name', required=True, validators=[Match(ANNOTATION_NAME)]),
            Str('value', required=True, validators=[Match(ANNOTATION_VALUE)]),
        )], default=[]),
        # the internal development record: user-defined container labels.
        List('labels', items=[Dict(
            'label',
            Str('name', required=True, validators=[Match(LABEL_NAME)]),
            Str('value', required=True, validators=[Match(LABEL_VALUE)]),
        )], default=[]),
        # the internal development record: provider runtime options from a catalog contract.
        Dict(
            'runtime',
            Int('stop_timeout', null=True, default=None, validators=[Range(min=0, max=MAX_STOP_TIMEOUT)]),
            # the internal development record: host names the container resolves to fixed addresses.
            List('extra_hosts', items=[Dict(
                'extra_host',
                Str('host', required=True, validators=[Match(HOST_ALIAS.pattern)]),
                IPAddr('address', required=True),
            )], default=[]),
            default={},
        ),
        # the internal development record: system certificates mounted into the application. The
        # operator's own list, like labels: a catalog entry never declares one.
        List('certificates', items=[Dict(
            'certificate',
            Int('id', required=True),
            Str('name', required=True, empty=False),
            Str('fingerprint', required=True, empty=False),
            Str('target', required=True, empty=False),
            Bool('restart_on_change', default=True),
            Int('uid', default=None, null=True, validators=[Range(min=0)]),
            Int('gid', default=None, null=True, validators=[Range(min=0)]),
        )], default=[]),
        Str('restart_policy', enum=['no', 'on-failure', 'always'], default='always'),
        Dict(
            'network',
            Str('mode', enum=['managed', 'lan'], default='managed'),
            Str('interface', default=None, null=True),
            Str('address', default=None, null=True),
            Str('gateway', default=None, null=True),
            Bool('managed_access', default=False),
            default={'mode': 'managed'},
        ),
        Dict(
            'portal',
            Str('scheme', enum=['http', 'https'], default='http'),
            Int('port', required=True, validators=[Range(min=1, max=65535)]),
            Str('path', default='/', validators=[Match(PORTAL_PATH)]),
            null=True, default=None,
        ),
        Dict(
            'healthcheck',
            Str('type', enum=['HTTP'], default='HTTP'),
            Str('scheme', enum=['http'], default='http'),
            Int('container_port', required=True, validators=[Range(min=1, max=65535)]),
            Int('host_port', required=True, null=True, validators=[Range(min=1, max=65535)]),
            Str('path', default='/', validators=[Match(PORTAL_PATH)]),
            null=True, default=None,
        ),
        Int('health_timeout', default=60, validators=[Range(min=0, max=300)]),
        Bool('acknowledge_unreviewed', default=False),
    ))
    @job(lock='applications_lifecycle')
    async def install(self, job, data):
        """Install an image the administrator points at (the internal development record, #444).

        This is the second tier beside the catalog: nothing here was reviewed by
        anyone but the administrator, and the acknowledgement says so. The record
        carries `origin.kind = "byo"` and is rendered as unreviewed. A Linux image
        additionally needs the experimental compatibility tier to be enabled.
        """
        if not data.pop('acknowledge_unreviewed'):
            verrors = ValidationErrors()
            verrors.add(
                'applications_install.acknowledge_unreviewed',
                'Confirm that this image is not reviewed by FreeCORE and that you own its '
                'supply chain from now on.',
            )
            verrors.check()
        origin = {
            'kind': 'byo',
            'reference': data['image'],
            'acknowledged_at': datetime.now(timezone.utc).isoformat(),
        }
        return await self._install_impl(job, data, None, origin)

    @lock('applications_lifecycle_internal')
    async def _require_linux_compat(self, config, image):
        """the internal development record: the gate for a Linux image, checked before any pull."""
        if not config.get('linux_compat_enabled'):
            raise CallError(
                'Linux images require the experimental Linux binary compatibility setting '
                '(Applications Settings). It is off on this system.'
            )
        status = await self.linux_compat_status(True)
        if not status['loaded']:
            raise CallError(
                'Linux binary compatibility is enabled but the Linux ABI is not loaded; '
                'save Applications Settings again or reboot.'
            )
        inspection = await inspect_remote_image(image, 'linux', 'amd64')
        reasons = image_refusals(inspection, 'linux', 'amd64')
        if reasons:
            raise CallError('Linux image refused: ' + '; '.join(reasons) + '.')

    async def _install_impl(self, job, data, catalog, origin=None):
        config = await self._require_config()
        await self._validate_install(config, data)
        network = self._network_request(data)
        if network.get('managed_access') or network['mode'] == 'managed':
            allocation_records, _ = self._read_records(config)
            pin = self._allocate_managed_leg_address(config, allocation_records)
            # the internal development record: a managed application keeps one bridge
            # address for its lifetime, so a gateway's routes stay valid.
            network['managed_address' if network['mode'] == 'lan' else 'bridge_address'] = pin
        image_os = data.get('image_os') or 'freebsd'
        if image_os == 'linux':
            await self._require_linux_compat(config, data['image'])
        created_datasets = []
        container_name = f'freecore-app-{data["name"]}'
        transaction_id = uuid.uuid4().hex
        # the internal development record: an image under localhost/ was built on this system
        # (a lifted jail); there is nothing to pull and nothing of it to roll back.
        local_image = data['image'].startswith('localhost/')
        image_preexisting = await self._image_exists(config, data['image'])
        if local_image and not image_preexisting:
            raise CallError(f'Local image {data["image"]!r} does not exist in the Applications store.')
        image_pull_attempted = False
        image_info = None
        created_container_id = None

        try:
            job.set_progress(10, 'Preparing application storage')
            volumes = await self._prepare_volumes(config, data, created_datasets)

            if local_image:
                job.set_progress(25, 'Using the locally built image')
            else:
                if image_os == 'linux':
                    job.set_progress(25, 'Pulling Linux OCI image (experimental compatibility tier)')
                    pull_platform = ['--os', 'linux', '--arch', 'amd64']
                else:
                    job.set_progress(25, 'Pulling native OCI image')
                    pull_platform = []
                image_pull_attempted = True
                await self._settle_before_reraise(
                    self._podman(config, 'pull', '--quiet', *pull_platform, '--', data['image'])
                )
            image_info = await self._inspect_image(
                config, data['image'], allow_linux=image_os == 'linux',
            )
            pulled_os = image_info.get('os') or image_os
            if pulled_os != image_os:
                raise CallError(
                    f'Pulled image reports operating system {pulled_os!r}, '
                    f'not the requested {image_os!r}.'
                )
            requested_digest = data['image'].rsplit('@', 1)[1] if '@' in data['image'] else None
            if requested_digest is not None and image_info['digest'] != requested_digest:
                raise CallError('Pulled OCI image digest does not match the requested immutable image.')
            if self._declared_runtime_owner(data.get('environment')) is None:
                image_owner = self._image_runtime_owner(image_info.get('env'))
                if image_owner is not None:
                    await self._give_new_volumes_to(volumes, created_datasets, image_owner)

            now = datetime.now(timezone.utc).isoformat()
            record = {
                'schema': 3,
                'image_os': image_os,
                'origin': copy.deepcopy(origin),
                'name': data['name'],
                'container_name': container_name,
                'container_id': None,
                'image': data['image'],
                'image_id': image_info['id'],
                'digest': image_info['digest'],
                'ports': data['ports'],
                'environment': data['environment'],
                'volumes': volumes,
                'annotations': data['annotations'],
                'labels': data.get('labels') or [],
                # the internal development record: only options that are set are recorded, in canonical form.
                'runtime': runtime_options(data.get('runtime')),
                'certificates': await self._bind_install_certificates(data.get('certificates') or []),
                'restart_policy': data['restart_policy'],
                'portal': data['portal'],
                'healthcheck': data['healthcheck'],
                'created_at': now,
                'updated_at': now,
            }
            # the internal development record: the record says what was pulled, not what
            # the review could read from the index.
            record['catalog'] = installed_catalog_provenance(catalog, image_info)
            record['schema'] = 4
            record['network'] = network
            record = self._validate_record(
                config, record, data['name'], allow_unbound_container=True,
            )

            await self._prepare_lan_network(config, record)
            # the internal development record: the bind-mount sources must exist before create.
            await self.render_certificates(record)
            job.set_progress(55, 'Creating application container')
            with temporary_environment_file(record) as environment_file:
                command = podman_create_args(
                    record, environment_file=environment_file,
                    transaction_id=transaction_id,
                )
                await self._settle_before_reraise(self._podman(
                    config, *command[1:],
                    redactions=[item['value'] for item in record.get('environment', [])],
                ))
            created_container = await self._inspect_owned_container(
                config,
                record,
                container=container_name,
                transaction_id=transaction_id,
                require_record_identity=False,
            )
            if created_container is None:
                raise CallError('Created application container is unavailable.')
            created_container_id = created_container[1]
            record['container_id'] = created_container_id
            record = self._validate_record(config, record, data['name'])
            await self._settle_before_reraise(
                self._podman(config, 'start', created_container_id)
            )

            job.set_progress(75, 'Checking application health')
            await self._wait_healthy(
                config, created_container_id, data['health_timeout'],
                self._record_healthcheck_probe(record),
                redactions=[item['value'] for item in record.get('environment', [])],
            )
            self._write_record(config, record)
            await self._settle_before_reraise(self._refresh_restart_on_boot(config))
        except BaseException as error:
            rollback_errors = await self._complete_ignoring_cancellation(
                self._rollback_install(
                    config, data, created_datasets, container_name, image_pull_attempted,
                    image_preexisting, image_info, transaction_id, created_container_id,
                )
            )
            if rollback_errors:
                message = getattr(error, 'errmsg', str(error)) or type(error).__name__
                raise CallError(
                    f'{message} Application installation rollback was incomplete: '
                    f'{"; ".join(rollback_errors)}'
                ) from error
            raise

        job.set_progress(100, 'Application installed')
        return await self._complete_ignoring_cancellation(
            self.middleware.call(
                'applications.query', [('name', '=', data['name'])], {'get': True}
            )
        )

    async def _rollback_install(
        self, config, data, created_datasets, container_name, image_pull_attempted,
        image_preexisting, image_info, transaction_id, created_container_id,
    ):
        errors = []
        try:
            await self._remove_transaction_container(
                config,
                {'name': data['name'], 'container_name': container_name},
                transaction_id,
                created_container_id,
            )
        except Exception as error:  # noqa: BLE001
            errors.append(f'remove attempted container: {error}')
        try:
            self._delete_record(config, data['name'])
        except FileNotFoundError:
            pass
        except Exception as error:  # noqa: BLE001
            errors.append(f'remove attempted record: {error}')
        try:
            self._remove_lan_conflist(config['pool'], data['name'])
        except Exception as error:  # noqa: BLE001
            errors.append(f'remove attempted LAN network: {error}')
        owner = f'applications:{data["name"]}'
        errors.extend(await self._delete_attempted_owned_datasets(
            created_datasets, {dataset: owner for dataset in created_datasets}
        ))
        if image_pull_attempted and not image_preexisting and image_info is not None:
            try:
                await self._podman(
                    config, 'image', 'rm', image_info['id']
                )
            except Exception as error:  # noqa: BLE001
                errors.append(f'remove newly pulled image: {error}')
        try:
            await self._refresh_restart_on_boot(config, force=True)
        except Exception as error:  # noqa: BLE001
            errors.append(f'restore restart intent: {error}')
        return errors

    async def _rollback_catalog_replacement(
        self, config, old_record, old_container_id, replacement_attempted,
        replacement_transaction_id, replacement_container_id, was_running, health_timeout,
        restart_intent_changed,
    ):
        container_name = old_record['container_name']
        errors = []
        old_available = False

        # Reconcile by immutable container ID and a per-create transaction label;
        # names are not ownership proof and may be claimed by an external Podman
        # caller while rollback is in progress.
        if replacement_attempted:
            try:
                await self._remove_transaction_container(
                    config,
                    old_record,
                    replacement_transaction_id,
                    replacement_container_id,
                )
            except Exception as error:  # noqa: BLE001
                errors.append(f'remove failed replacement safely: {error}')

        if old_container_id is not None:
            try:
                if not await self._container_exists(config, old_container_id):
                    raise CallError('Prior container is unavailable by immutable ID.')
                old = await self._inspect_container(config, old_container_id)
                restored_id = self._validate_owned_container_inspection(old_record, old)
                if restored_id != old_container_id:
                    raise CallError('Prior container identity changed during rollback.')
                if await self._container_exists(config, container_name):
                    occupant = await self._inspect_container(config, container_name)
                    if occupant.get('Id') != old_container_id:
                        raise CallError(
                            f'Container name {container_name!r} is occupied by '
                            'an unrelated container.'
                        )
                else:
                    await self._podman(
                        config, 'rename', old_container_id, container_name
                    )
                old_available = True
            except Exception as error:  # noqa: BLE001
                errors.append(f'restore prior container name: {error}')

        if was_running and old_available:
            try:
                inspection = await self._inspect_container(config, old_container_id)
                if not (inspection.get('State') or {}).get('Running'):
                    await self._prepare_lan_network(config, old_record)
                    await self._podman(config, 'start', old_container_id)
                await self._wait_healthy(
                    config, old_container_id, health_timeout,
                    self._record_healthcheck_probe(old_record),
                    redactions=[item['value'] for item in old_record.get('environment', [])],
                )
            except Exception as error:  # noqa: BLE001
                errors.append(f'restart prior container: {error}')

        try:
            self._write_record(config, old_record)
        except Exception as error:  # noqa: BLE001
            errors.append(f'restore installed record: {error}')
        if restart_intent_changed:
            try:
                await self._refresh_restart_on_boot(config, force=True)
            except Exception as error:  # noqa: BLE001
                errors.append(f'restore restart intent: {error}')
        return errors

    @lock('applications_lifecycle_internal')
    @private
    @job(lock='applications_lifecycle')
    async def update_catalog(
        self, job, expected_record, replacement, catalog, health_timeout,
    ):
        config = await self._require_config()
        current = self._get_record(config, expected_record.get('name'))
        if current != expected_record:
            raise CallError(
                'The installed application changed after catalog review; review it again.'
            )
        expected_replacement_fields = {
            'annotations',
            'environment',
            'healthcheck',
            'image',
            'name',
            'portal',
            'ports',
            'restart_policy',
            'volumes',
        }
        # the internal development record: 'labels' is optional here -- a replacement built before it
        # existed is still a valid one and means "no labels".
        # the internal development record: 'certificates' likewise.
        optional_replacement_fields = {'labels', 'certificates', 'runtime'}
        if (
            not isinstance(replacement, dict) or
            set(replacement) - optional_replacement_fields != expected_replacement_fields or
            replacement['name'] != current['name'] or
            type(health_timeout) is not int or not 0 <= health_timeout <= 300
        ):
            raise CallError('Catalog replacement request is invalid.')

        container_name = current['container_name']
        # the internal development record: the catalog follows the provider's tag, so the
        # replacement is normally a tag and the pulled digest is what gets recorded.
        # An explicit immutable reference is still held to its digest.
        requested_digest = (
            replacement['image'].rsplit('@', 1)[1]
            if isinstance(replacement.get('image'), str) and '@' in replacement['image'] else None
        )

        job.set_progress(10, 'Pulling updated native OCI image')
        await self._settle_before_reraise(
            self._podman(config, 'pull', '--quiet', '--', replacement['image'])
        )
        image_info = await self._inspect_image(config, replacement['image'])
        if requested_digest is not None and image_info['digest'] != requested_digest:
            raise CallError('Pulled OCI image digest does not match the requested immutable image.')

        now = datetime.now(timezone.utc).isoformat()
        new_record = {
            'schema': 3,
            'image_os': 'freebsd',
            'origin': copy.deepcopy(current.get('origin')),
            'name': current['name'],
            'container_name': container_name,
            'container_id': None,
            'image': replacement['image'],
            'image_id': image_info['id'],
            'digest': image_info['digest'],
            'ports': copy.deepcopy(replacement['ports']),
            'environment': copy.deepcopy(replacement['environment']),
            'volumes': copy.deepcopy(replacement['volumes']),
            'annotations': copy.deepcopy(replacement['annotations']),
            'labels': copy.deepcopy(replacement.get('labels') or []),
            'runtime': copy.deepcopy(replacement.get('runtime') or {}),
            # the internal development record: the operator's mounted certificates survive a
            # catalog update, as labels and environment values do.
            'certificates': copy.deepcopy(replacement.get('certificates') or []),
            'restart_policy': replacement['restart_policy'],
            'portal': copy.deepcopy(replacement['portal']),
            'healthcheck': copy.deepcopy(replacement['healthcheck']),
            'created_at': current['created_at'],
            'updated_at': now,
            'catalog': installed_catalog_provenance(catalog, image_info),
        }
        # the internal development record/#484: the attachment is the administrator's, not
        # the catalog's; an update carries it forward and pins a managed
        # application that predates pinning, since its container is recreated anyway.
        network = copy.deepcopy(current.get('network') or {'mode': 'managed'})
        if network['mode'] == 'managed' and not network.get('bridge_address'):
            allocation_records, _ = self._read_records(config)
            network['bridge_address'] = self._allocate_managed_leg_address(
                config, allocation_records, current['name'],
            )
        if current.get('schema', 3) < 3:
            new_record.setdefault('image_os', 'freebsd')
            new_record.setdefault('origin', None)
        new_record['schema'] = 4
        new_record['network'] = network
        new_record = self._validate_record(
            config, new_record, current['name'], allow_unbound_container=True,
        )
        await self._replace_container(job, config, current, new_record, health_timeout, 'update')
        if current.get('image_id') != new_record.get('image_id'):
            # the internal development record: the image the update superseded is nobody's now.
            await self._complete_ignoring_cancellation(
                self._release_image(config, current.get('image_id'))
            )

        job.set_progress(100, 'Application update complete')
        return await self._complete_ignoring_cancellation(
            self.middleware.call(
                'applications.query', [('name', '=', current['name'])], {'get': True}
            )
        )

    async def _replace_container(self, job, config, current, new_record, health_timeout, operation):
        """Swap the application's container for one built from ``new_record``.

        Stop and rename the current container as a rollback point, create and
        start the replacement under a fresh transaction label, wait for its
        health, restore the previous running/stopped state and commit the
        record; on any failure roll back to the old container (which is only
        removed once the new one is committed).  Shared by the catalog update
        and by reconfigure (the internal development record).  ``operation`` names the
        job in progress and error text.
        """
        container_name = current['container_name']
        restart_intent_changed = (
            new_record['restart_policy'] != current['restart_policy']
        )

        old_container = await self._inspect_owned_container(config, current)
        old_container_id = old_container[1] if old_container is not None else None
        was_running = False
        if old_container is not None:
            inspection = old_container[0]
            was_running = bool((inspection.get('State') or {}).get('Running'))
        desired_running = was_running or old_container_id is None

        backup_name = None
        previous_conflist = None
        conflist_prepared = False
        certificates_rendered = False
        replacement_attempted = False
        replacement_container_id = None
        replacement_transaction_id = uuid.uuid4().hex
        try:
            job.set_progress(35, 'Preparing transactional container replacement')
            if old_container_id is not None:
                backup_name = f'{container_name}-rollback-{uuid.uuid4().hex[:12]}'
                if was_running:
                    await self._settle_before_reraise(
                        self._podman(config, 'stop', old_container_id)
                    )
                await self._settle_before_reraise(
                    self._podman(config, 'rename', old_container_id, backup_name)
                )

            previous_conflist = await self._prepare_lan_network(config, new_record)
            # the internal development record: the replacement's entries may differ from the
            # current ones, so its directories are rendered before it is created.
            certificates_rendered = True
            await self.render_certificates(new_record)
            conflist_prepared = (new_record.get('network') or {}).get('mode') == 'lan'
            replacement_attempted = True
            with temporary_environment_file(new_record) as environment_file:
                command = podman_create_args(
                    new_record, environment_file=environment_file,
                    transaction_id=replacement_transaction_id,
                )
                await self._settle_before_reraise(self._podman(
                    config, *command[1:],
                    redactions=[item['value'] for item in new_record.get('environment', [])],
                ))
            replacement_container = await self._inspect_owned_container(
                config,
                new_record,
                container=container_name,
                transaction_id=replacement_transaction_id,
                require_record_identity=False,
            )
            if replacement_container is None:
                raise CallError('Replacement application container is unavailable.')
            replacement_container_id = replacement_container[1]
            new_record['container_id'] = replacement_container_id
            new_record = self._validate_record(config, new_record, current['name'])
            await self._settle_before_reraise(
                self._podman(config, 'start', replacement_container_id)
            )

            job.set_progress(70, 'Checking replacement application health')
            await self._wait_healthy(
                config, replacement_container_id, health_timeout,
                self._record_healthcheck_probe(new_record),
                redactions=[item['value'] for item in new_record.get('environment', [])],
            )
            if not desired_running:
                await self._settle_before_reraise(
                    self._podman(config, 'stop', replacement_container_id)
                )

            self._write_record(config, new_record)
            if (
                (current.get('network') or {}).get('mode') == 'lan' and
                (new_record.get('network') or {}).get('mode') != 'lan'
            ):
                self._remove_lan_conflist(config['pool'], current['name'])
            if restart_intent_changed:
                await self._settle_before_reraise(
                    self._refresh_restart_on_boot(config)
                )
        except BaseException as error:
            if conflist_prepared:
                try:
                    self._restore_lan_conflist(config['pool'], current['name'], previous_conflist)
                except Exception:  # noqa: BLE001
                    self.logger.warning(
                        'Unable to restore the LAN network of application %r',
                        current['name'], exc_info=True,
                    )
            certificate_errors = []
            if certificates_rendered:
                # the internal development record: the replacement's render rewrote, or pruned, the
                # directories the prior container mounts; its own files go back before the
                # rollback starts it again.
                try:
                    await self._complete_ignoring_cancellation(self.render_certificates(current))
                except Exception as render_error:  # noqa: BLE001
                    certificate_errors.append(f'restore mounted certificates: {render_error}')
            rollback_errors = certificate_errors + await self._complete_ignoring_cancellation(
                self._rollback_catalog_replacement(
                    config,
                    current,
                    old_container_id,
                    replacement_attempted,
                    replacement_transaction_id,
                    replacement_container_id,
                    was_running,
                    health_timeout,
                    restart_intent_changed,
                )
            )
            if rollback_errors:
                message = getattr(error, 'errmsg', str(error)) or type(error).__name__
                raise CallError(
                    f'{message} Application {operation} rollback was incomplete: '
                    f'{"; ".join(rollback_errors)}'
                ) from error
            raise

        if old_container_id is not None:
            try:
                await self._complete_ignoring_cancellation(
                    self._podman(config, 'rm', '--force', old_container_id)
                )
            except Exception:
                self.logger.warning(
                    'Replaced the container of application %r but could not remove its '
                    'stopped rollback container %r', current['name'], backup_name, exc_info=True,
                )
        if current.get('certificates') or new_record.get('certificates'):
            # the internal development record: the replacement rendered and came up.
            await self._clear_certificate_alerts(current['name'])

    @accepts(Str('name', validators=[Match(APPLICATION_NAME)]))
    async def inspect(self, name):
        await self._require_config()
        return await self.middleware.call(
            'applications.query', [('name', '=', name)], {'get': True}
        )

    @lock('applications_lifecycle_internal')
    @accepts(Str('name', validators=[Match(APPLICATION_NAME)]))
    @job(lock='applications_lifecycle')
    async def start(self, job, name):
        config = await self._require_config()
        record = self._get_record(config, name)
        container_id = (await self._require_owned_container(config, record))[1]
        await self._prepare_lan_network(config, record)
        # the internal development record: /var/run is tmpfs, so the files are gone after a
        # reboot; every start renders them again from the certificate store.
        await self.render_certificates(record)
        await self._complete_ignoring_cancellation(
            self._podman(config, 'start', container_id)
        )
        if record.get('certificates'):
            await self._clear_certificate_alerts(record['name'])
        return True

    @lock('applications_lifecycle_internal')
    @accepts(Str('name', validators=[Match(APPLICATION_NAME)]))
    @job(lock='applications_lifecycle')
    async def stop(self, job, name):
        config = await self._require_config()
        record = self._get_record(config, name)
        container_id = (await self._require_owned_container(config, record))[1]
        await self._complete_ignoring_cancellation(
            self._podman(config, 'stop', container_id)
        )
        return True

    @lock('applications_lifecycle_internal')
    @accepts(Str('name', validators=[Match(APPLICATION_NAME)]))
    @job(lock='applications_lifecycle')
    async def restart(self, job, name):
        config = await self._require_config()
        record = self._get_record(config, name)
        container_id = (await self._require_owned_container(config, record))[1]
        await self._prepare_lan_network(config, record)
        await self.render_certificates(record)
        await self._complete_ignoring_cancellation(
            self._podman(config, 'restart', container_id)
        )
        if record.get('certificates'):
            await self._clear_certificate_alerts(record['name'])
        return True

    @accepts(
        Str('name', validators=[Match(APPLICATION_NAME)]),
        Int('tail', default=200, validators=[Range(min=1, max=10000)]),
    )
    async def logs(self, name, tail):
        config = await self._require_config()
        record = self._get_record(config, name)
        container_id = (await self._require_owned_container(config, record))[1]
        cp = await self._podman(
            config, 'logs', '--tail', str(tail), container_id
        )
        return cp.stdout

    async def _owned_tree(self, dataset, owner):
        cp = await run(
            ['zfs', 'list', '-H', '-r', '-o', 'name', dataset],
            check=False,
            encoding='utf8',
        )
        if cp.returncode:
            detail = (cp.stderr or cp.stdout or '').strip()
            raise CallError(f'Unable to inspect application dataset {dataset!r}: {detail}')
        datasets = [line for line in cp.stdout.splitlines() if line]
        for child in datasets:
            if await self._dataset_owner(child) != owner:
                raise CallError(
                    f'Refusing to remove {dataset!r}; {child!r} is not owned by this application.'
                )
        return datasets

    @lock('applications_lifecycle_internal')
    @accepts(
        Str('name', validators=[Match(APPLICATION_NAME)]),
        Dict('options', Bool('remove_data', default=False), default={}),
    )
    @job(lock='applications_lifecycle')
    async def remove(self, job, name, options):
        config = await self._require_config()
        record = self._get_record(config, name)
        paths = application_paths(config['pool'])
        app_dataset = f'{paths["data_dataset"]}/{name}'
        owner = f'applications:{name}'
        remove_dataset = False

        if options['remove_data']:
            remove_dataset = await self._dataset_exists(app_dataset)
            if remove_dataset:
                await self._owned_tree(app_dataset, owner)

        destructive_phase = asyncio.ensure_future(self._remove_impl(
            config, record, app_dataset, remove_dataset,
        ))
        try:
            await asyncio.shield(destructive_phase)
        except asyncio.CancelledError:
            try:
                await self._complete_ignoring_cancellation(destructive_phase)
            except BaseException as error:
                detail = getattr(error, 'errmsg', str(error)) or type(error).__name__
                raise CallError(
                    f'Removal of application {name!r} was interrupted and could not '
                    f'finish safely: {detail}'
                ) from error
            raise
        return True

    # the internal development record: images are reference-counted by id across records.
    # The shared lift bases (#446) and any image a stored conversion plan still
    # names for its migration hop are never candidates.
    LIFT_BASE_REPOSITORY = 'localhost/freecore/jail-base'

    def _referenced_images(self, config, except_record=None):
        """Image ids the records still need, plus references a stored plan names."""
        records, _ = self._read_records(config)
        ids = set()
        references = set()
        for record in records:
            if except_record is not None and record['name'] == except_record:
                continue
            if isinstance(record.get('image_id'), str):
                ids.add(record['image_id'])
            if isinstance(record.get('image'), str):
                references.add(record['image'])
        for plan in self._stored_plans(config):
            hop = plan.get('hop') if isinstance(plan, dict) else None
            if isinstance(hop, dict) and isinstance(hop.get('image'), str):
                references.add(hop['image'])
        return ids, references

    def _stored_plans(self, config):
        try:
            directory = os.path.join(application_paths(config['pool'])['records'], 'convert')
            plans = []
            for name in os.listdir(directory):
                if name.endswith('.json'):
                    with open(os.path.join(directory, name), 'rb') as file:
                        plans.append(json.loads(file.read(1024 * 1024)))
            return plans
        except (OSError, ValueError):
            return []

    async def _release_image(self, config, image_id, except_record=None):
        """Remove an image once no record uses it; a failure is logged, never raised.

        Decided by image id: after an update the record's tag names the new
        image, and the superseded one has no name left.  A lift base or a hop
        image is never a record's image, so neither can arrive here.
        """
        if not isinstance(image_id, str) or not image_id:
            return False
        try:
            ids, _ = self._referenced_images(config, except_record)
            if image_id in ids:
                return False
            result = await self._podman(config, 'rmi', image_id, check=False)
        except Exception:  # noqa: BLE001
            self.logger.warning('Unable to release image %s', image_id[:12], exc_info=True)
            return False
        if result.returncode:
            self.logger.warning(
                'Image %s of application %r stays: %s', image_id[:12], except_record,
                (result.stderr or result.stdout or '').strip()[-512:],
            )
            return False
        return True

    @accepts(Dict(
        'options',
        Bool('dry_run', default=False),
        # the internal development record: also destroy app-owned datasets no application
        # maps.  Off by default; nothing under the store is touched without it.
        Bool('data', default=False),
        default={},
    ))
    @job(lock='applications_lifecycle')
    async def prune(self, job, options):
        """Remove images no application needs (the internal development record), and with
        ``data`` the app-owned datasets no application maps (the internal development record).

        Kept: every image a record's id or reference names, the lift base images,
        an image a stored conversion plan names for its hop, and anything a
        container (managed or not) still uses.  `dry_run` reports without removing.
        """
        config = await self._require_config()
        orphans = await self.orphaned_data() if options.get('data') else []
        ids, references = self._referenced_images(config)
        listing = await self._podman(config, 'images', '--format', 'json')
        try:
            images = json.loads(listing.stdout or '[]')
        except ValueError as error:
            raise CallError('Unable to read the image store.') from error
        containers = await self._podman(config, 'ps', '--all', '--no-trunc', '--format', 'json')
        try:
            in_use = {
                entry.get('ImageID') for entry in json.loads(containers.stdout or '[]') if isinstance(entry, dict)
            }
        except ValueError:
            in_use = set()
        candidates = []
        for image in images if isinstance(images, list) else []:
            if not isinstance(image, dict) or not isinstance(image.get('Id'), str):
                continue
            image_id = image['Id']
            names = [name for name in (image.get('Names') or []) if isinstance(name, str)]
            if (
                image_id in ids or image_id in in_use or
                any(name in references for name in names) or
                any(name.startswith(self.LIFT_BASE_REPOSITORY + ':') for name in names)
            ):
                continue
            candidates.append({
                'id': image_id, 'names': names, 'size': int(image.get('Size') or 0),
                'dangling': not names or bool(image.get('Dangling')),
            })
        total = sum(item['size'] for item in candidates)
        if options['dry_run']:
            return {
                'images': candidates, 'datasets': orphans,
                'reclaimable': total + self._orphan_bytes(orphans),
                'removed': 0, 'dry_run': True,
            }
        removed = 0
        errors = []
        if orphans:
            # Volumes before their parents: the deletion helper walks its list in
            # reverse and refuses a dataset whose owner stamp is not the application's.
            ordered = sorted(orphans, key=lambda item: (not item['parent'], item['dataset']))
            deletion_errors = await self._delete_attempted_owned_datasets(
                [item['dataset'] for item in ordered],
                {item['dataset']: f'applications:{item["application"]}' for item in ordered},
            )
            errors.extend(deletion_errors)
            for item in orphans:
                item['removed'] = not any(item['dataset'] in error for error in deletion_errors) \
                    and not await self._dataset_exists(item['dataset'])
            removed += self._orphan_bytes([item for item in orphans if item['removed']])
        for item in candidates:
            # Untag by name so a multi-tagged image goes without --force (which
            # would also take containers); a dangling image has only its id.
            result = await self._podman(config, 'rmi', *(item['names'] or [item['id']]), check=False)
            if result.returncode:
                errors.append(f'{item["id"][:12]}: {(result.stderr or result.stdout or "").strip()[-200:]}')
                item['removed'] = False
            else:
                removed += item['size']
                item['removed'] = True
        job.set_progress(100, 'Image prune complete')
        return {
            'images': candidates, 'datasets': orphans, 'reclaimable': total,
            'removed': removed, 'dry_run': False, 'errors': errors,
        }

    async def _remove_impl(self, config, record, app_dataset, remove_dataset):
        # Keep the record until every destructive external operation has
        # completed. A failed call is therefore safely retryable, including when
        # Podman or ZFS completed but its response was interrupted.
        await self._remove_owned_container(config, record)
        origin = record.get('origin') or {}
        if isinstance(origin, dict) and origin.get('image_owned') and isinstance(origin.get('image'), str):
            # the internal development record: the lifted image belongs to this application alone;
            # its base layer is shared and stays. A failure here is not worth a stuck removal.
            result = await self._podman(config, 'rmi', '--force', origin['image'], check=False)
            if result.returncode:
                self.logger.warning(
                    'Unable to remove owned image %s: %s', origin['image'], (result.stderr or '').strip()[-512:],
                )
        else:
            # the internal development record: the last application on an image takes it along.
            await self._release_image(config, record.get('image_id'), record['name'])
        if remove_dataset and await self._dataset_exists(app_dataset):
            # Revalidate the complete tree immediately before destruction. The
            # earlier check is only a preflight and is not deletion authority.
            owner = f'applications:{record["name"]}'
            datasets = await self._owned_tree(app_dataset, owner)
            deletion_errors = await self._delete_attempted_owned_datasets(
                datasets, {dataset: owner for dataset in datasets}
            )
            if deletion_errors:
                raise CallError(
                    f'Application data removal was incomplete: '
                    f'{"; ".join(deletion_errors)}'
                )
        self._remove_lan_conflist(config['pool'], record['name'])
        # the internal development record: the rendered keys go with the application, data or not.
        await self.middleware.run_in_thread(self._remove_certificate_files, record['name'])
        if record.get('certificates'):
            await self._clear_certificate_alerts(record['name'])
        self._delete_record(config, record['name'])
        try:
            await self._refresh_restart_on_boot(config)
        except BaseException as error:
            rollback_errors = []
            try:
                self._write_record(config, record)
            except Exception as rollback_error:  # noqa: BLE001
                rollback_errors.append(f'restore installed record: {rollback_error}')
            try:
                await self._refresh_restart_on_boot(config, force=True)
            except Exception as rollback_error:  # noqa: BLE001
                rollback_errors.append(f'restore restart intent: {rollback_error}')
            if rollback_errors:
                message = getattr(error, 'errmsg', str(error)) or type(error).__name__
                raise CallError(
                    f'{message} Application removal rollback was incomplete: '
                    f'{"; ".join(rollback_errors)}'
                ) from error
            raise

    @private
    async def _running_managed(self, config, strict=False):
        records, errors = self._read_records(config)
        if strict and errors:
            raise CallError(
                'Unable to classify Applications state safely because managed records are invalid: '
                f'{", ".join(sorted(error["name"] for error in errors))}.'
            )

        running = []
        inspected = await self._inspect_managed_containers(config, records)
        for record in records:
            try:
                owned = inspected.get(record['name'])
                if isinstance(owned, CallError):
                    raise owned
                if owned is None:
                    continue
                inspection = owned[0]
                if (inspection.get('State') or {}).get('Running'):
                    running.append(record['name'])
            except Exception as error:
                if strict:
                    raise CallError(
                        f'Unable to classify application {record["name"]!r} safely: {error}'
                    ) from error
                self.logger.warning(
                    'Unable to inspect managed application %r', record['name'], exc_info=True
                )
        return sorted(set(running))

    @private
    async def _stop_managed(self, config):
        records, errors = self._read_records(config)
        failed = [error['name'] for error in errors]
        for error in errors:
            self.logger.warning(
                'Unable to stop managed application %r: %s',
                error['name'], error['error'],
            )
        for record in records:
            try:
                owned = await self._inspect_owned_container(config, record)
                if owned is not None:
                    await self._podman(config, 'stop', owned[1])
            except Exception:
                failed.append(record['name'])
                self.logger.warning(
                    'Failed to stop managed application %r', record['name'], exc_info=True
                )
        return failed

    @private
    @lock('applications_lifecycle_internal')
    async def stop_all(self):
        config = await self.config()
        if not config['pool'] or not config['runtime_ready']:
            return
        return not await self._stop_managed(config)

    @private
    @lock('applications_lifecycle_internal')
    async def runtime_teardown(self):
        config = await self.config()
        if not config['pool']:
            return False

        return await self._runtime_teardown_impl(config)

    async def _runtime_teardown_impl(self, config, *, stop=True):
        failed = await self._stop_managed(config) if stop and config['runtime_ready'] else []
        self._clear_runtime_state()
        cleanup_errors = await self._restore_runtime_sysctls(config)
        try:
            await self.middleware.call('etc.generate', 'rc')
        except Exception as error:
            cleanup_errors.append(f'generate rc: {error}')
            self.logger.warning('Failed to generate rc during Applications teardown', exc_info=True)
        try:
            await _generate_pf_checked(self.middleware)
        except Exception as error:
            cleanup_errors.append(f'generate pf: {error}')
            self.logger.warning('Failed to generate pf during Applications teardown', exc_info=True)
        try:
            await self._disable_owned_pf(config)
        except Exception as error:
            cleanup_errors.append(f'disable owned PF: {error}')
            self.logger.warning('Failed to disable Applications-owned PF', exc_info=True)

        if failed or cleanup_errors:
            detail = []
            if failed:
                detail.append(f'workloads not stopped: {", ".join(sorted(failed))}')
            detail.extend(cleanup_errors)
            raise CallError(f'Applications teardown was incomplete ({"; ".join(detail)}).')
        return True

    @private
    @lock('applications_lifecycle_internal')
    async def start_on_boot(self):
        if self._pool_transition() is not None:
            return
        return await self._start_on_boot_impl()

    async def _start_on_boot_impl(self):
        config = await self.config()
        if not config['runtime_ready'] or not config['restart_on_boot']:
            return
        records, _ = self._read_records(config)
        # the internal development record: tmpfs is empty after a boot, so every application that
        # mounts a certificate is rendered again -- including one that is not started here,
        # so that an operator-driven start later finds its files.
        for record in records:
            if record.get('certificates'):
                try:
                    await self.render_certificates(record)
                except Exception as error:  # noqa: BLE001
                    # The start below fails for want of its mount source; say why where the
                    # operator looks, not only in the log.
                    self.logger.warning(
                        'Failed to render certificates for application %r', record['name'],
                        exc_info=True,
                    )
                    await self.middleware.call(
                        'alert.oneshot_create', 'ApplicationsCertificateRenderFailed',
                        {'application': record['name'], 'error': str(error)},
                    )
                else:
                    await self._clear_certificate_alerts(
                        record['name'], ('ApplicationsCertificateRenderFailed',),
                    )
        records = [record for record in records if record.get('restart_policy') == 'always']
        inspected = await self._inspect_managed_containers(config, records)
        for record in records:
            try:
                owned = inspected.get(record['name'])
                if isinstance(owned, CallError):
                    raise owned
                if owned is None:
                    raise CallError(
                        f'Managed container {record["container_name"]!r} is unavailable.'
                    )
                inspection = owned[0]
                if not (inspection.get('State') or {}).get('Running'):
                    await self._prepare_lan_network(config, record)
                    await self._podman(config, 'start', owned[1])
            except Exception:
                self.logger.warning(
                    'Failed to start managed application %r', record['name'], exc_info=True
                )

    def _attachment_records(self, config):
        records, errors = self._read_records(config)
        if errors:
            raise CallError('Applications storage contains invalid managed records; pool detachment is unsafe.')
        return records

    async def _store_guid(self, pool):
        result = await run(
            ['zfs', 'get', '-Hp', '-o', 'value', 'guid', application_paths(pool)['dataset']],
            check=False, encoding='utf8',
        )
        guid = result.stdout.strip()
        if result.returncode or not re.fullmatch(r'[1-9][0-9]*', guid):
            raise CallError('Unable to verify Applications storage identity.')
        return guid

    async def _attachment_containers(self, config, records):
        running = {}
        inspected = await self._inspect_managed_containers(config, records)
        for record in records:
            owned = inspected.get(record['name'])
            if isinstance(owned, CallError):
                raise owned
            if owned is None:
                raise CallError(
                    f'Managed container {record["container_name"]!r} is unavailable.'
                )
            inspection, container_id = owned
            state = (inspection.get('State') or {}).get('Running')
            if type(state) is not bool:
                raise CallError(f'Unable to classify application {record["name"]!r} running state.')
            if state:
                running[record['name']] = container_id
        return running

    @private
    @lock('applications_lifecycle_internal')
    async def pool_attachments(self, path):
        config = await self.config()
        if not config['pool']:
            return []
        root = application_paths(config['pool'])['mountpoint']
        if is_child(root, path):
            return [{'id': 'applications:store', 'name': 'Applications', 'pool': config['pool']}]
        if is_child(path, root):
            return [{'id': 'applications:store-child', 'name': 'Applications storage',
                     'pool': config['pool'], 'protected': True}]
        state = self._pool_transition()
        if state is None:
            # Missing record storage must not look like an empty collection of
            # external dataset references after a pool becomes unavailable.
            await self._validate_application_store(config['pool'])
        records = state['records'] if state is not None else self._attachment_records(config)
        return [
            {'id': f'applications:{record["name"]}:{volume["name"]}',
             'name': f'{record["name"]}: {volume["dataset"]}', 'pool': config['pool'], 'protected': True}
            for record in records for volume in record['volumes'] if not volume['owned'] and any(
                is_child(source, path) or is_child(path, source)
                for source in {volume['source'], f'/mnt/{volume["dataset"]}'}
            )
        ]

    @private
    @lock('applications_lifecycle_internal')
    async def stop_for_pool(self, pool):
        config = await self.config()
        if config['pool'] != pool:
            return False
        if self._pool_transition() is not None:
            raise CallError('Applications pool transition is already in progress.')
        await self._validate_application_store(pool)
        self._validate_managed_configs(pool, config['subnet'])
        records = self._attachment_records(config)
        running = await self._attachment_containers(config, records)
        guid = await self._store_guid(pool)
        self._export_state = {'config': copy.deepcopy(config), 'records': copy.deepcopy(records),
                              'running': running, 'guid': guid}
        # Keep the gate after partial failure. The pool export coordinator may
        # restore this exact snapshot only while the original pool is available.
        failed = await self._settle_before_reraise(self._stop_managed(config))
        if failed or await self._attachment_containers(config, records):
            raise CallError('Applications workloads could not all be stopped; pool detachment is unsafe.')
        await self._settle_before_reraise(self._runtime_teardown_impl(config, stop=False))
        return True

    @private
    @lock('applications_lifecycle_internal')
    async def rollback_pool_export(self, pool):
        state = self._pool_transition()
        if state is None:
            return True  # Validation failed before any Applications mutation.
        config = await self.config()
        previous = state['config']
        if config['pool'] != pool or previous['pool'] != pool:
            raise CallError('Applications pool selection changed during export recovery.')
        await self._validate_application_store(pool)
        if await self._store_guid(pool) != state['guid']:
            raise CallError('Applications store identity changed during export recovery.')
        self._validate_managed_configs(pool, previous['subnet'])
        records = self._attachment_records(config)
        if (records != state['records'] or config['subnet'] != previous['subnet'] or
                config['restart_on_boot'] != previous['restart_on_boot']):
            raise CallError('Applications records or network changed during export recovery.')
        await self._attachment_containers(config, records)
        if previous['runtime_ready']:
            if not await self._runtime_setup_impl(allow_pool_transition=True):
                raise CallError('Applications runtime could not be restored on this controller.')
        elif state['running']:
            raise CallError('Applications were running without a ready runtime; recovery requires attention.')
        for record in records:
            if record['name'] in state['running']:
                owned = await self._require_owned_container(config, record)
                if owned[1] != state['running'][record['name']]:
                    raise CallError('Applications container identity changed during export recovery.')
                if not owned[0]['State']['Running']:
                    await self._settle_before_reraise(self._podman(config, 'start', owned[1]))
        if await self._attachment_containers(config, records) != state['running']:
            raise CallError('Applications running state could not be restored after export failure.')
        self._export_state = None
        return True

    @private
    @lock('applications_lifecycle_internal')
    async def pool_available(self, pool=None):
        config = await self.config()
        if not config['pool'] or pool is not None and pool != config['pool']:
            return False
        if not await self._active_controller():
            return False
        await self._validate_application_store(config['pool'])
        self._attachment_records(config)
        state = self._pool_transition()
        if state is not None and await self._store_guid(config['pool']) != state['guid']:
            raise CallError('Applications store identity changed while its pool was unavailable.')
        if not await self._runtime_setup_impl(allow_pool_transition=True):
            return False
        self._export_state = None
        await self._start_on_boot_impl()
        return True

    @private
    @lock('applications_lifecycle_internal')
    async def interface_sync(self):
        if self._pool_transition() is not None:
            return
        config = await self.config()
        if not config['pool'] or not await self.middleware.call('system.ready'):
            return
        try:
            if config['runtime_ready']:
                await _generate_pf_checked(self.middleware)
            elif await self._runtime_setup_impl():
                await self._start_on_boot_impl()
        except Exception:
            try:
                await self._runtime_teardown_impl(config)
            except Exception:
                self.logger.warning('Applications cleanup after interface recovery failed', exc_info=True)
            try:
                await self.middleware.call('alert.oneshot_create', 'ApplicationsRuntimeSetupFailed', None)
            except Exception:
                self.logger.warning('Unable to create Applications runtime alert', exc_info=True)
            raise
        try:
            await self.middleware.call('alert.oneshot_delete', 'ApplicationsRuntimeSetupFailed', None)
        except Exception:
            self.logger.debug('Unable to clear Applications runtime alert', exc_info=True)


class ApplicationsFSAttachmentDelegate(FSAttachmentDelegate):
    name = 'applications'
    title = 'Applications'

    async def query(self, path, enabled, options=None):
        return await self.middleware.call('applications.pool_attachments', path)

    @staticmethod
    def _require_store(attachments):
        if any(item.get('protected') for item in attachments):
            raise CallError(
                'This dataset is referenced by Applications. Remove the affected applications '
                'before detaching it.'
            )

    async def stop(self, attachments):
        self._require_store(attachments)
        if attachments:
            await self.middleware.call('applications.stop_for_pool', attachments[0]['pool'])

    async def start(self, attachments):
        if attachments and not any(item.get('protected') for item in attachments):
            await self.middleware.call('applications.pool_available', attachments[0]['pool'])

    async def toggle(self, attachments, enabled):
        if enabled:
            await self.start(attachments)
        else:
            await self.stop(attachments)

    async def delete(self, attachments):
        if not attachments:
            return
        if any(item['id'] == 'applications:store-child' for item in attachments):
            raise CallError(
                'This dataset is part of the Applications store. Unconfigure Applications '
                '(applications.unconfigure) before destroying it.'
            )
        if any(item.get('protected') for item in attachments):
            raise CallError(
                'This dataset is referenced by installed applications. Remove those '
                'applications before destroying it.'
            )
        # the internal development record: the whole store is inside what is being deleted with
        # cascade; that is the explicit removal, the datasets go with the pool operation.
        await self.middleware.call('applications.deactivate_pool', attachments[0]['pool'])

    async def rollback_export(self, attachments):
        if any(item.get('protected') for item in attachments):
            return True  # stop() refused this attachment before any mutation.
        return not attachments or await self.middleware.call(
            'applications.rollback_pool_export', attachments[0]['pool'],
        )


async def _runtime_setup_with_alert(middleware):
    try:
        configured = await middleware.call('applications.runtime_setup')
    except Exception:
        middleware.logger.exception('Failed to prepare native Applications runtime')
        try:
            await middleware.call('alert.oneshot_create', 'ApplicationsRuntimeSetupFailed', None)
        except Exception:
            middleware.logger.debug(
                'Unable to create Applications runtime alert during early boot', exc_info=True
            )
        return False
    try:
        await middleware.call('alert.oneshot_delete', 'ApplicationsRuntimeSetupFailed', None)
    except Exception:
        middleware.logger.debug(
            'Unable to clear Applications runtime alert during early boot', exc_info=True
        )
    return configured


async def _system_event(middleware, event_type, args):
    if args['id'] == 'ready':
        if await _runtime_setup_with_alert(middleware):
            # ix-etc renders rc.conf before data pools are available. Replay
            # managed boot intent once their pool and network are actually ready.
            await middleware.call('applications.start_on_boot')
    elif args['id'] == 'shutdown':
        await middleware.call('applications.stop_all')


async def _pool_pre_lock(middleware, pool):
    config = await middleware.call('applications.config')
    if config['pool'] == pool['name']:
        await middleware.call('applications.stop_for_pool', pool['name'])


async def _pool_post_import(middleware, pool):
    config = await middleware.call('applications.config')
    if (
        config['pool'] and
        await middleware.call('system.ready') and
        (pool is None or config['pool'] == pool['name']) and
        await middleware.call('applications.pool_available', pool['name'] if pool else None)
    ):
        return


async def _interface_post_sync(middleware):
    await middleware.call('applications.interface_sync')


async def setup(middleware):
    await middleware.call('pool.dataset.register_attachment_delegate', ApplicationsFSAttachmentDelegate(middleware))
    middleware.register_hook('pool.pre_lock', _pool_pre_lock)
    middleware.register_hook('pool.post_import', _pool_post_import)
    middleware.register_hook('pool.post_unlock', _pool_post_import)
    middleware.register_hook('interface.post_sync', _interface_post_sync)
    middleware.event_subscribe('system', _system_event)

    config = await middleware.call('applications.config')
    if (
        config['pool'] and
        await middleware.call('system.ready') and
        await _runtime_setup_with_alert(middleware)
    ):
        await middleware.call('applications.start_on_boot')
