import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from middlewared.plugins.reporting.guests import (
    GuestStatsSampler, app_container_names, is_bastille_jail_path, parse_cpu_time,
    parse_jail_inventory, parse_jail_rows, parse_options, parse_process_rows, setup,
)
from middlewared.service import CallError


@pytest.mark.parametrize(('value', 'seconds'), [
    ('00:01', 1),
    ('01:02.50', 62.5),
    ('03:04:05', 11045),
    ('2-03:04:05.25', 183845.25),
])
def test_parse_cpu_time(value, seconds):
    assert parse_cpu_time(value) == seconds


@pytest.mark.parametrize('arg', ['[]', '{', '{"interval": true}', '{"interval": 1}', '{"interval": NaN}'])
def test_invalid_options_fail_closed(arg):
    with pytest.raises(CallError):
        parse_options(arg)


def test_options_default_and_custom_interval():
    assert parse_options(None) == {'interval': 5}
    assert parse_options('{"interval": 2.5}') == {'interval': 2.5}


def test_process_rows_use_bytes_and_reject_malformed_samples():
    assert parse_process_rows(' 3 41 1024 1-02:03:04.50\n') == [{
        'jid': 3,
        'pid': 41,
        'rss': 1048576,
        'cpu_time': 93784.5,
    }]
    with pytest.raises(CallError):
        parse_process_rows('3 41 malformed')
    with pytest.raises(CallError):
        parse_process_rows('-1 41 1024 00:01')


def test_process_rows_accept_freebsd_kernel_pid_zero():
    # Captured columns from FreeBSD ps with one -o option per empty header.
    assert parse_process_rows('0    0   3472   0:02.22\n0    1   1344   0:00.22\n') == [
        {'jid': 0, 'pid': 0, 'rss': 3472 * 1024, 'cpu_time': 2.22},
        {'jid': 0, 'pid': 1, 'rss': 1344 * 1024, 'cpu_time': 0.22},
    ]


@pytest.mark.parametrize('output', [
    ',pid=,rss=,time=\n               0\n',  # FreeBSD treats this as a renamed JID header.
    '0 -1 3472 0:02.22\n',
    '1 0 3472 0:02.22\n',  # PID 0 is the host kernel, never a jail process.
    '0 1 -1 0:02.22\n',
    '0 1 3472 invalid\n',
    '0 1 3472 0:02.22 extra\n',
])
def test_process_rows_still_reject_invalid_samples(output):
    with pytest.raises(CallError):
        parse_process_rows(output)


def test_jail_rows_strip_only_the_iocage_prefix():
    assert parse_jail_rows(json.dumps({
        'jail-information': {'jail': [
            {'jid': 3, 'name': 'ioc-plex'},
            {'jid': 4, 'name': 'bastille-db'},
        ]},
    })) == {3: 'plex', 4: 'bastille-db'}


class Middleware:

    def __init__(self, apps=None):
        self.calls = []
        # the internal development record: an identity refresh also asks which jails are
        # Applications containers. Hosts without applications answer with none.
        self.apps = apps if apps is not None else []

    def call_sync(self, method):
        self.calls.append(method)
        if method == 'applications.query':
            return self.apps
        assert method == 'vm.query'
        return [
            {
                'id': 2, 'name': 'stopped', 'memory': 512, 'vcpus': 1,
                'status': {'state': 'STOPPED', 'pid': None},
            },
            {
                'id': 1, 'name': 'builder', 'memory': 4096, 'vcpus': 2, 'cores': 2, 'threads': 1,
                'status': {'state': 'RUNNING', 'pid': 100},
            },
        ]


def command_results(ps_output, jails=None):
    if jails is None:
        jails = [{'jid': 7, 'name': 'ioc-web'}]

    def run(command, **kwargs):
        assert kwargs == {'capture_output': True, 'text': True, 'check': False}
        if command[0] == '/usr/sbin/jls':
            stdout = json.dumps({'jail-information': {'jail': jails}})
        else:
            assert command == ['/bin/ps', '-axo', 'jid=', '-o', 'pid=', '-o', 'rss=', '-o', 'time=']
            stdout = ps_output
        return SimpleNamespace(returncode=0, stdout=stdout, stderr='')
    return run


def test_first_sample_attributes_memory_and_primes_cpu_deltas():
    sampler = GuestStatsSampler()
    middleware = Middleware()
    output = '0 0 3472 0:02.22\n0 100 4096 00:10\n7 201 1024 00:03\n7 202 2048 00:04\n0 999 8192 00:20\n'

    with patch('middlewared.plugins.reporting.guests.subprocess.run', side_effect=command_results(output)), \
            patch('middlewared.plugins.reporting.guests.psutil.cpu_count', return_value=4), \
            patch('middlewared.plugins.reporting.guests.psutil.virtual_memory', return_value=SimpleNamespace(
                total=16 * 1024 ** 3, free=4 * 1024 ** 3,
            )), patch('middlewared.plugins.reporting.guests.arc_size', return_value=2 * 1024 ** 3), \
            patch('middlewared.plugins.reporting.guests.time.monotonic', return_value=10):
        payload = sampler.sample(middleware, 5)

    assert payload['cpu_count'] == 4
    assert payload['vms'] == [
        {
            'id': 1, 'name': 'builder', 'state': 'RUNNING', 'provisioned': 4096 * 1024 ** 2,
            'vcpus': 4, 'cpu_pct': None, 'rss': 4096 * 1024,
        },
        {'id': 2, 'name': 'stopped', 'state': 'STOPPED', 'provisioned': 512 * 1024 ** 2, 'vcpus': 1},
    ]
    assert payload['jails'] == [{
        'jid': 7, 'name': 'web', 'cpu_pct': None, 'rss': 3072 * 1024, 'nproc': 2,
    }]
    assert payload['services_bytes'] == 10 * 1024 ** 3
    assert payload['attributed_bytes'] == 7168 * 1024
    assert middleware.calls == ['vm.query', 'applications.query']


def test_empty_guest_inventory_emits_valid_empty_stats_with_freebsd_processes():
    sampler = GuestStatsSampler()
    middleware = Mock()
    middleware.call_sync.return_value = []
    output = '0    0   3472   0:02.22\n0    1   1344   0:00.22\n'

    with patch('middlewared.plugins.reporting.guests.subprocess.run',
               side_effect=command_results(output, jails=[])) as run, \
            patch('middlewared.plugins.reporting.guests.psutil.cpu_count', return_value=2), \
            patch('middlewared.plugins.reporting.guests.psutil.virtual_memory', return_value=SimpleNamespace(
                total=4 * 1024 ** 3, free=1024 ** 3,
            )), patch('middlewared.plugins.reporting.guests.arc_size', return_value=1024 ** 3), \
            patch('middlewared.plugins.reporting.guests.time.monotonic', return_value=10):
        payload = sampler.sample(middleware, 5)

    assert payload == {
        'cpu_count': 2, 'vms': [], 'jails': [], 'apps': [], 'bastille': [],
        'services_bytes': 2 * 1024 ** 3, 'attributed_bytes': 0,
    }
    assert run.call_count == 2
    assert [call.args[0] for call in middleware.call_sync.call_args_list] == [
        'vm.query', 'applications.query',
    ]


def test_second_sample_reports_share_of_host_and_cache_is_shared():
    sampler = GuestStatsSampler()
    middleware = Middleware()
    first = '0 0 3472 00:00\n0 100 4096 00:10\n7 201 1024 00:03\n'
    second = '0 0 3472 00:08\n0 100 4096 00:12\n7 201 1024 00:04\n'
    results = [
        command_results(first)(['/usr/sbin/jls'], capture_output=True, text=True, check=False),
        command_results(first)(
            ['/bin/ps', '-axo', 'jid=', '-o', 'pid=', '-o', 'rss=', '-o', 'time='],
            capture_output=True, text=True, check=False,
        ),
        command_results(second)(
            ['/bin/ps', '-axo', 'jid=', '-o', 'pid=', '-o', 'rss=', '-o', 'time='],
            capture_output=True, text=True, check=False,
        ),
    ]

    with patch('middlewared.plugins.reporting.guests.subprocess.run', side_effect=results) as run, \
            patch('middlewared.plugins.reporting.guests.psutil.cpu_count', return_value=4), \
            patch('middlewared.plugins.reporting.guests.psutil.virtual_memory', return_value=SimpleNamespace(
                total=8 * 1024 ** 3, free=2 * 1024 ** 3,
            )), patch('middlewared.plugins.reporting.guests.arc_size', return_value=1024 ** 3), \
            patch('middlewared.plugins.reporting.guests.time.monotonic', side_effect=[10, 11, 12]):
        first_payload = sampler.sample(middleware, 2)
        cached_payload = sampler.sample(middleware, 2)
        second_payload = sampler.sample(middleware, 2)

    assert first_payload['vms'][0]['cpu_pct'] is None
    assert cached_payload == first_payload
    assert second_payload['vms'][0]['cpu_pct'] == 25.0
    assert second_payload['jails'][0]['cpu_pct'] == 12.5
    assert run.call_count == 3
    assert middleware.calls == ['vm.query', 'applications.query']


def test_unknown_jid_forces_identity_refresh_without_a_second_process_sweep():
    sampler = GuestStatsSampler()
    middleware = Middleware()
    output = '8 301 1024 00:01\n'
    jails = [
        SimpleNamespace(returncode=0, stdout='{"jail-information":{"jail":[]}}', stderr=''),
        SimpleNamespace(
            returncode=0,
            stdout='{"jail-information":{"jail":[{"jid":8,"name":"new-jail"}]}}', stderr='',
        ),
    ]

    def run(command, **kwargs):
        if command[0] == '/usr/sbin/jls':
            return jails.pop(0)
        return SimpleNamespace(returncode=0, stdout=output, stderr='')

    with patch('middlewared.plugins.reporting.guests.subprocess.run', side_effect=run) as process_run, \
            patch('middlewared.plugins.reporting.guests.psutil.cpu_count', return_value=2), \
            patch('middlewared.plugins.reporting.guests.psutil.virtual_memory', return_value=SimpleNamespace(
                total=4 * 1024 ** 3, free=1024 ** 3,
            )), patch('middlewared.plugins.reporting.guests.arc_size', return_value=0), \
            patch('middlewared.plugins.reporting.guests.time.monotonic', return_value=10):
        payload = sampler.sample(middleware, 5)

    assert payload['jails'][0]['name'] == 'new-jail'
    assert process_run.call_count == 3
    assert middleware.calls == [
        'vm.query', 'applications.query', 'vm.query', 'applications.query',
    ]


def test_app_container_names_maps_ids_and_survives_a_host_without_applications():
    middleware = Middleware(apps=[
        {'container_id': 'a' * 64, 'name': 'openspeedtest'},
        {'name': 'no container id'},
        {'container_id': '', 'name': 'blank'},
    ])
    assert app_container_names(middleware) == {'a' * 64: 'openspeedtest'}

    failing = Mock()
    failing.call_sync.side_effect = RuntimeError('applications are not configured')
    assert app_container_names(failing) == {}


def test_an_application_is_reported_as_an_app_not_a_jail_named_by_its_container_id():
    # An Applications container runs in a jail whose name is its container id.
    container_id = '662c2016f524ec5063993d21e8ff4a9a49a7a7e64724f7fa91a4fbcf9089848f'
    middleware = Middleware(apps=[{'container_id': container_id, 'name': 'openspeedtest'}])
    sampler = GuestStatsSampler()
    run = command_results('  0 100 4096 00:01\n  9 200 2048 00:02\n', jails=[
        {'jid': 9, 'name': container_id},
    ])

    with patch('middlewared.plugins.reporting.guests.subprocess.run', side_effect=run), \
            patch('middlewared.plugins.reporting.guests.psutil.cpu_count', return_value=2), \
            patch('middlewared.plugins.reporting.guests.psutil.virtual_memory', return_value=SimpleNamespace(
                total=4 * 1024 ** 3, free=1024 ** 3,
            )), patch('middlewared.plugins.reporting.guests.arc_size', return_value=0), \
            patch('middlewared.plugins.reporting.guests.time.monotonic', return_value=10):
        payload = sampler.sample(middleware, 5)

    assert payload['jails'] == []
    assert [row['name'] for row in payload['apps']] == ['openspeedtest']
    # The card exists to attribute memory, so an app still counts toward it.
    assert payload['apps'][0]['rss'] == 2048 * 1024
    # The running VM's own host process is attributed alongside it.
    assert payload['attributed_bytes'] == 4096 * 1024 + 2048 * 1024


def test_a_plain_jail_is_untouched_when_no_application_claims_it():
    middleware = Middleware(apps=[{'container_id': 'b' * 64, 'name': 'other-app'}])
    sampler = GuestStatsSampler()
    run = command_results('  0 100 4096 00:01\n  9 200 2048 00:02\n', jails=[
        {'jid': 9, 'name': 'ioc-web'},
    ])

    with patch('middlewared.plugins.reporting.guests.subprocess.run', side_effect=run), \
            patch('middlewared.plugins.reporting.guests.psutil.cpu_count', return_value=2), \
            patch('middlewared.plugins.reporting.guests.psutil.virtual_memory', return_value=SimpleNamespace(
                total=4 * 1024 ** 3, free=1024 ** 3,
            )), patch('middlewared.plugins.reporting.guests.arc_size', return_value=0), \
            patch('middlewared.plugins.reporting.guests.time.monotonic', return_value=10):
        payload = sampler.sample(middleware, 5)

    assert [row['name'] for row in payload['jails']] == ['web']
    assert payload['apps'] == []


def test_setup_registers_public_contract():
    middleware = Mock()

    setup(middleware)

    name, source = middleware.register_event_source.call_args.args
    assert name == 'guest.stats'
    assert source.__name__ == 'GuestStatsEventSource'


# the internal development record: Bastille jails are their own family, decided by path.


@pytest.mark.parametrize(('path', 'expected'), [
    ('/mnt/tank/bastille/jails/web/root', True),
    ('/mnt/tank/bastille/jails/web/root/', True),
    ('/usr/local/bastille/jails/web/root', True),
    ('/mnt/tank/iocage/jails/web/root', False),
    ('/mnt/tank/bastille/jails/web', False),
    ('/mnt/tank/bastille/jails/../iocage/jails/web/root', False),
    ('', False),
    (None, False),
])
def test_bastille_jail_paths_are_recognised_by_layout_only(path, expected):
    assert is_bastille_jail_path(path) is expected


def test_jail_inventory_keeps_paths_and_jail_rows_still_return_names():
    output = json.dumps({'jail-information': {'jail': [
        {'jid': 7, 'name': 'ioc-web', 'path': '/mnt/tank/iocage/jails/web/root'},
        {'jid': 8, 'name': 'smokenginx', 'path': '/mnt/tank/bastille/jails/smokenginx/root'},
        {'jid': 9, 'name': 'nopath'},
    ]}})
    assert parse_jail_inventory(output) == {
        7: {'name': 'web', 'path': '/mnt/tank/iocage/jails/web/root'},
        8: {'name': 'smokenginx', 'path': '/mnt/tank/bastille/jails/smokenginx/root'},
        9: {'name': 'nopath', 'path': ''},
    }
    assert parse_jail_rows(output) == {7: 'web', 8: 'smokenginx', 9: 'nopath'}


def test_a_bastille_jail_is_reported_in_its_own_family_by_path():
    middleware = Middleware(apps=[{'container_id': 'b' * 64, 'name': 'other-app'}])
    sampler = GuestStatsSampler()
    run = command_results('  0 100 4096 00:01\n  9 200 2048 00:02\n  10 300 1024 00:03\n', jails=[
        {'jid': 9, 'name': 'ioc-web', 'path': '/mnt/tank/iocage/jails/web/root'},
        {'jid': 10, 'name': 'smokenginx', 'path': '/mnt/tank/bastille/jails/smokenginx/root'},
    ])

    with patch('middlewared.plugins.reporting.guests.subprocess.run', side_effect=run), \
            patch('middlewared.plugins.reporting.guests.psutil.cpu_count', return_value=2), \
            patch('middlewared.plugins.reporting.guests.psutil.virtual_memory', return_value=SimpleNamespace(
                total=4 * 1024 ** 3, free=1024 ** 3,
            )), patch('middlewared.plugins.reporting.guests.arc_size', return_value=0), \
            patch('middlewared.plugins.reporting.guests.time.monotonic', return_value=10):
        payload = sampler.sample(middleware, 5)

    assert [row['name'] for row in payload['jails']] == ['web']
    assert payload['apps'] == []
    assert payload['bastille'] == [{
        'jid': 10, 'name': 'smokenginx', 'cpu_pct': None, 'rss': 1024 * 1024, 'nproc': 1,
    }]
    # The card exists to attribute memory, so a Bastille jail still counts toward it.
    assert payload['attributed_bytes'] == 4096 * 1024 + 2048 * 1024 + 1024 * 1024
