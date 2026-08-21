"""vm.device.pptdev_choices reads pciconf on every call (the internal development record).

The list used to be filled once per middlewared process, so a device bound to ppt at runtime stayed
"not available" to vm.start until middlewared restarted. Off-box: pciconf is a stub.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import patch

from middlewared.plugins import vm as vm_plugin
from middlewared.plugins.vm import VMDeviceService

GPU_ON_HOST = 'vgapci1@pci0:68:0:0:\tclass=0x030000 rev=0xa1 hdr=0x00 vendor=0x10de device=0x2531\n'
GPU_ON_PPT = 'ppt1@pci0:68:0:0:\tclass=0x030000 rev=0xa1 hdr=0x00 vendor=0x10de device=0x2531\n'
HDA_ON_PPT = 'ppt0@pci0:68:0:1:\tclass=0x040300 rev=0xa1 hdr=0x00 vendor=0x10de device=0x228e\n'
NIC = 'ix0@pci0:1:0:0:\tclass=0x020000 rev=0x01 hdr=0x00 vendor=0x8086 device=0x10fb\n'


def service():
    svc = object.__new__(VMDeviceService)
    svc.pptdevs = {}
    return svc


def pciconf(*outputs):
    calls = iter(outputs)

    async def run(*args, **kwargs):
        assert args == ('/usr/sbin/pciconf', '-l')
        return SimpleNamespace(returncode=0, stdout=next(calls).encode(), stderr=b'')
    return run


def choices(svc):
    return asyncio.run(svc.pptdev_choices())


def test_a_device_bound_to_ppt_at_runtime_appears_without_a_restart():
    svc = service()
    with patch.object(vm_plugin, 'run', pciconf(GPU_ON_HOST + HDA_ON_PPT + NIC, GPU_ON_PPT + HDA_ON_PPT + NIC)):
        assert choices(svc) == {'68/0/1': '68/0/1'}
        assert choices(svc) == {'68/0/0': '68/0/0', '68/0/1': '68/0/1'}


def test_a_device_released_from_ppt_disappears():
    svc = service()
    with patch.object(vm_plugin, 'run', pciconf(GPU_ON_PPT + HDA_ON_PPT, GPU_ON_HOST + HDA_ON_PPT)):
        assert set(choices(svc)) == {'68/0/0', '68/0/1'}
        assert choices(svc) == {'68/0/1': '68/0/1'}


def test_no_ppt_device_gives_an_empty_list():
    svc = service()
    with patch.object(vm_plugin, 'run', pciconf(GPU_ON_HOST + NIC)):
        assert choices(svc) == {}
