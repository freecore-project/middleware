"""vm.get_available_memory subtracts used swap in bytes, the unit psutil reports it in.

Off-box like test_vm_bhyve_devices: the service is built without a middleware, and
overcommit=True keeps it from asking the middleware about running guests.
"""
from types import SimpleNamespace
from unittest.mock import patch

from middlewared.plugins import vm as vm_module
from middlewared.plugins.vm import VMService


GiB = 1024 * 1024 * 1024
MiB = 1024 * 1024


def available_memory(available, swap_used, arc_size=0, arc_min=0):
    sysctls = {
        'kstat.zfs.misc.arcstats.size': arc_size,
        'vfs.zfs.arc.min': arc_min,
    }
    service = object.__new__(VMService)
    with (
        patch.object(vm_module, '_sysctl_int', sysctls.get),
        patch.object(vm_module.psutil, 'virtual_memory', return_value=SimpleNamespace(available=available)),
        patch.object(vm_module.psutil, 'swap_memory', return_value=SimpleNamespace(used=swap_used)),
    ):
        return service.get_available_memory(True)


def test_used_swap_is_subtracted_as_bytes():
    # 100 MiB of swap in use takes 100 MiB off the answer, not 100 MiB * hw.pagesize (400 GiB)
    assert available_memory(16 * GiB, 100 * MiB) == int(16 * GiB * 0.9) - 100 * MiB


def test_used_swap_does_not_hide_shrinkable_arc():
    assert available_memory(16 * GiB, 1 * MiB, arc_size=6 * GiB, arc_min=2 * GiB) == (
        int(16 * GiB * 0.9) + 4 * GiB - 1 * MiB
    )


def test_no_swap_in_use():
    assert available_memory(16 * GiB, 0) == int(16 * GiB * 0.9)
