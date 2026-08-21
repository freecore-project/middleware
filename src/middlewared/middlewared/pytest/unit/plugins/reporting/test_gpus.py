from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from middlewared.plugins.reporting.gpus import (
    AMDGPU_INFO_SENSOR_GPU_LOAD,
    AMDGPU_INFO_SENSOR_GPU_TEMP,
    AmdgpuHeapInfo,
    GpuStatsSampler,
    attach_dri_nodes,
    collect_amdgpu,
    dri_bus_ids,
    normalize_pci,
    parse_fstat,
    parse_nvidia_smi_xml,
    parse_options,
    parse_pciconf,
    setup,
)
from middlewared.plugins.reporting.guests import GUEST_IDENTITIES, SAMPLER as GUEST_SAMPLER, GuestIdentityCache
from middlewared.service import CallError


PCICONF = """\
vgapci0@pci0:3:0:0: class=0x030000 rev=0xa1 hdr=0x00 vendor=0x10de device=0x2531 subvendor=0x10de
    vendor     = 'NVIDIA Corporation'
    device     = 'RTX A2000'
    class      = display
hostb0@pci0:0:0:0: class=0x060000 rev=0x01 hdr=0x00 vendor=0x8086 device=0x1234
    vendor     = 'Intel Corporation'
    device     = 'Host bridge'
    class      = bridge
vgapci1@pci0:9:0:0: class=0x030000 rev=0xc1 hdr=0x00 vendor=0x1002 device=0x73ff subvendor=0x1002
    vendor     = 'Advanced Micro Devices, Inc. [AMD/ATI]'
    device     = 'Navi 23'
    class      = display
"""

NVIDIA_XML = """\
<nvidia_smi_log>
  <driver_version>550.54</driver_version>
  <gpu id="00000000:03:00.0">
    <product_name>NVIDIA RTX A2000</product_name>
    <pci><pci_bus_id>00000000:03:00.0</pci_bus_id></pci>
    <fb_memory_usage><total>6144 MiB</total><used>2176 MiB</used></fb_memory_usage>
    <utilization>
      <gpu_util>38 %</gpu_util><encoder_util>12 %</encoder_util><decoder_util>0 %</decoder_util>
    </utilization>
    <temperature><gpu_temp>62 C</gpu_temp></temperature>
    <processes>
      <process_info>
        <pid>101</pid><process_name>/usr/local/bin/ffmpeg</process_name><used_memory>1930 MiB</used_memory>
      </process_info>
      <process_info>
        <pid>102</pid><process_name>/usr/local/bin/transcode</process_name><used_memory>128 MiB</used_memory>
      </process_info>
    </processes>
  </gpu>
</nvidia_smi_log>
"""

FSTAT = """\
USER CMD PID FD MOUNT INUM MODE SZ|DV R/W NAME
root ffmpeg 101 4 /dev 12 crw 0x0 rw /dev/dri/renderD128
root transcode 102 5 /dev 12 crw 0x0 rw /dev/dri/card0
root bhyve 400 6 /dev 12 crw 0x0 rw /dev/dri/renderD128
"""


class IdentityCache:

    def __init__(self, passthrough=None):
        self.calls = []
        self.identities = {
            'vms': [],
            'vm_by_pid': {400: {'id': 12, 'name': 'buildvm'}},
            'jails': {7: 'plex'},
            'passthrough': passthrough or {},
        }

    def snapshot(self, middleware, now, force=False):
        self.calls.append((now, force))
        return self.identities


@pytest.mark.parametrize('arg', ['[]', '{', '{"interval": true}', '{"interval": 1}', '{"interval": NaN}'])
def test_invalid_options_fail_closed(arg):
    with pytest.raises(CallError):
        parse_options(arg)


def test_options_default_and_custom_interval():
    assert parse_options(None) == {'interval': 5}
    assert parse_options('{"interval": 2.5}') == {'interval': 2.5}


def test_pci_inventory_filters_display_devices_and_maps_dri_nodes():
    devices = attach_dri_nodes(parse_pciconf(PCICONF), [
        '/dev/dri/renderD129', '/dev/dri/card0', '/dev/dri/renderD128', '/dev/dri/card1',
    ])

    assert normalize_pci('00000000:03:00.0', 16) == '3:0:0'
    assert [(device['id'], device['vendor'], device['driver'], device['name']) for device in devices] == [
        ('3:0:0', 'nvidia', 'vgapci', 'RTX A2000'),
        ('9:0:0', 'amd', 'vgapci', 'Navi 23'),
    ]
    assert devices[0]['nodes'] == ['card0', 'renderD128']
    assert devices[1]['nodes'] == ['card1', 'renderD129']


def test_dri_bus_ids_prevent_driverless_gpu_from_shifting_node_ownership():
    values = [
        SimpleNamespace(name='hw.dri.0.busid', value='pci:0000:09:00.0'),
        SimpleNamespace(name='hw.dri.0.modesetting', value=1),
    ]
    with patch('middlewared.plugins.reporting.gpus.sysctl', SimpleNamespace(filter=lambda prefix: values)):
        bus_ids = dri_bus_ids()

    devices = attach_dri_nodes(
        parse_pciconf(PCICONF), ['/dev/dri/card0', '/dev/dri/renderD128'], bus_ids,
    )
    assert bus_ids == {0: '9:0:0'}
    assert devices[0]['nodes'] == []
    assert devices[1]['nodes'] == ['card0', 'renderD128']


def test_fstat_deduplicates_processes_per_gpu():
    consumers = parse_fstat(FSTAT, {
        '/dev/dri/card0': '3:0:0',
        '/dev/dri/renderD128': '3:0:0',
    })

    assert consumers == {'3:0:0': {101: 'ffmpeg', 102: 'transcode', 400: 'bhyve'}}


def test_nvidia_xml_exposes_tier_one_telemetry_and_process_memory():
    gpu = parse_nvidia_smi_xml(NVIDIA_XML)['3:0:0']

    assert gpu == {
        'name': 'NVIDIA RTX A2000',
        'driver_version': '550.54',
        'util_pct': 38.0,
        'enc_pct': 12.0,
        'dec_pct': 0.0,
        'vram_used': 2176 * 1024 ** 2,
        'vram_total': 6144 * 1024 ** 2,
        'temp_c': 62.0,
        'processes': {
            101: {'name': 'ffmpeg', 'gpu_mem': 1930 * 1024 ** 2},
            102: {'name': 'transcode', 'gpu_mem': 128 * 1024 ** 2},
        },
    }


def test_amdgpu_ctypes_collector_queries_load_vram_and_temperature():
    library = FakeAmdgpuLibrary()

    with patch('middlewared.plugins.reporting.gpus.os.open', return_value=42), \
            patch('middlewared.plugins.reporting.gpus.os.close') as close:
        result = collect_amdgpu('/dev/dri/renderD128', library)

    assert result == {
        'util_pct': 37,
        'enc_pct': None,
        'dec_pct': None,
        'vram_used': 2 * 1024 ** 3,
        'vram_total': 8 * 1024 ** 3,
        'temp_c': 62.0,
        'processes': {},
    }
    assert library.initialized_with == 42
    assert library.deinitialized
    close.assert_called_once_with(42)


def test_amdgpu_heap_layout_matches_libdrm_abi():
    assert [field[0] for field in AmdgpuHeapInfo._fields_] == [
        'heap_size', 'heap_usage', 'max_allocation',
    ]


def test_sampler_shares_sweeps_and_rolls_up_jail_vm_and_host_consumers():
    identities = IdentityCache()
    sampler = GpuStatsSampler(identities)

    def run(command, **kwargs):
        assert kwargs == {'capture_output': True, 'text': True, 'check': False}
        if command == ['/usr/sbin/pciconf', '-lv']:
            output = PCICONF.split('vgapci1@', 1)[0]
        elif command[0] == '/usr/bin/fstat':
            output = FSTAT
        else:
            assert command == ['/usr/local/bin/nvidia-smi', '-q', '-x']
            output = NVIDIA_XML
        return SimpleNamespace(returncode=0, stdout=output, stderr='')

    with (
        patch('middlewared.plugins.reporting.gpus.subprocess.run', side_effect=run) as process_run,
        patch('middlewared.plugins.reporting.gpus.glob.glob', side_effect=[
            ['/dev/dri/card0'], ['/dev/dri/renderD128'],
        ]),
        patch('middlewared.plugins.reporting.gpus.dri_bus_ids', return_value={0: '3:0:0'}),
        patch(
            'middlewared.plugins.reporting.gpus.process_jid', side_effect=lambda pid: 7 if pid == 101 else 0,
        ),
        patch('middlewared.plugins.reporting.gpus.time.monotonic', side_effect=[10, 11, 12]),
    ):
        first = sampler.sample(Mock(), 2)
        cached = sampler.sample(Mock(), 2)
        second = sampler.sample(Mock(), 2)

    assert cached == first
    assert first['gpus'][0] == {
        'id': '3:0:0',
        'name': 'NVIDIA RTX A2000',
        'vendor': 'nvidia',
        'driver': 'nvidia-drm 550.54',
        'nodes': ['card0', 'renderD128'],
        'state': 'active',
        'passthrough_vm': None,
        'util_pct': 38.0,
        'enc_pct': 12.0,
        'dec_pct': 0.0,
        'vram_used': 2176 * 1024 ** 2,
        'vram_total': 6144 * 1024 ** 2,
        'temp_c': 62.0,
        'users': [
            {'kind': 'jail', 'name': 'plex', 'procs': 1, 'gpu_mem': 1930 * 1024 ** 2},
            {'kind': 'host', 'name': 'transcode', 'procs': 1, 'gpu_mem': 128 * 1024 ** 2},
            {'kind': 'vm', 'name': 'buildvm', 'procs': 1},
        ],
    }
    assert second == first
    assert process_run.call_count == 5  # inventory + two steady-state execs per fresh sample
    assert identities.calls == [(10, False), (12, False)]


def test_passthrough_owner_suppresses_host_collectors():
    pciconf = PCICONF.replace('vgapci0@', 'ppt0@').split('hostb0@', 1)[0]
    sampler = GpuStatsSampler(IdentityCache({'3:0:0': {'id': 12, 'name': 'buildvm'}}))

    with patch('middlewared.plugins.reporting.gpus.subprocess.run', return_value=SimpleNamespace(
        returncode=0, stdout=pciconf, stderr='',
    )) as process_run, patch('middlewared.plugins.reporting.gpus.glob.glob', return_value=[]), \
            patch('middlewared.plugins.reporting.gpus.time.monotonic', return_value=10):
        gpu = sampler.sample(Mock(), 5)['gpus'][0]

    assert gpu['state'] == 'passthrough'
    assert gpu['passthrough_vm'] == {'id': 12, 'name': 'buildvm'}
    assert gpu['util_pct'] is None
    assert gpu['users'] == []
    assert process_run.call_count == 1


def test_guest_identity_cache_is_shared_and_includes_passthrough_ownership():
    cache = GuestIdentityCache()
    middleware = Mock()
    middleware.call_sync.return_value = [{
        'id': 12,
        'name': 'buildvm',
        'memory': 4096,
        'vcpus': 2,
        'cores': 1,
        'threads': 1,
        'status': {'state': 'RUNNING', 'pid': 400},
        'devices': [{'dtype': 'PCI', 'attributes': {'pptdev': '3/0/0'}}],
    }]
    jails = '{"jail-information":{"jail":[{"jid":7,"name":"ioc-plex"}]}}'

    with patch('middlewared.plugins.reporting.guests.subprocess.run', return_value=SimpleNamespace(
        returncode=0, stdout=jails, stderr='',
    )) as process_run:
        first = cache.snapshot(middleware, 10)
        second = cache.snapshot(middleware, 11)

    assert second == first
    assert first['vm_by_pid'][400]['name'] == 'buildvm'
    assert first['jails'] == {7: 'plex'}
    assert first['passthrough'] == {'3:0:0': {'id': 12, 'name': 'buildvm'}}
    # One refresh, two identity lookups: vm.query and, since
    # the internal development record, applications.query. The second snapshot is
    # served from the cache, which is what this asserts.
    assert middleware.call_sync.call_count == 2
    assert process_run.call_count == 1
    assert GUEST_SAMPLER.identity_cache is GUEST_IDENTITIES


def test_setup_registers_public_contract():
    middleware = Mock()

    setup(middleware)

    name, source = middleware.register_event_source.call_args.args
    assert name == 'gpu.stats'
    assert source.__name__ == 'GpuStatsEventSource'


class FakeAmdgpuLibrary:

    def __init__(self):
        self.initialized_with = None
        self.deinitialized = False

    def amdgpu_device_initialize(self, descriptor, major, minor, device):
        self.initialized_with = descriptor
        major._obj.value = 3
        minor._obj.value = 54
        device._obj.value = 123
        return 0

    def amdgpu_query_sensor_info(self, device, sensor_type, size, value):
        assert device.value == 123
        value._obj.value = {
            AMDGPU_INFO_SENSOR_GPU_LOAD: 37,
            AMDGPU_INFO_SENSOR_GPU_TEMP: 62000,
        }[sensor_type]
        return 0

    def amdgpu_query_heap_info(self, device, domain, flags, heap):
        assert device.value == 123
        heap._obj.heap_size = 8 * 1024 ** 3
        heap._obj.max_allocation = 6 * 1024 ** 3
        heap._obj.heap_usage = 2 * 1024 ** 3
        return 0

    def amdgpu_device_deinitialize(self, device):
        assert device.value == 123
        self.deinitialized = True
        return 0
