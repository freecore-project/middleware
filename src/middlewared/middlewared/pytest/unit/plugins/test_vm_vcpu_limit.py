"""The most virtual CPUs a VM can have is what this system can run, not a fixed 16.

the internal development record, 15.0 leg (bhyve guests only on this line): the hypervisor's hw.vmm.maxcpu, the host's thread
count by default. Off-box: the sysctl is a stub, and the validation runs with a stub middleware.
"""
from types import SimpleNamespace

import pytest

from middlewared.plugins import vm as vm_module
from middlewared.plugins.vm import VMService, bhyve_max_vcpus
from middlewared.service_exception import ValidationErrors

FLAGS = {'intel_vmx': True, 'unrestricted_guest': True, 'amd_rvi': False, 'amd_asids': False}


def sysctls(monkeypatch, **values):
    monkeypatch.setattr(vm_module, '_sysctl_val', lambda name: values.get(name.replace('.', '_')))


@pytest.mark.parametrize('values,expected', [
    ({'hw_vmm_maxcpu': 48, 'hw_ncpu': 48}, 48),
    ({'hw_vmm_maxcpu': 64, 'hw_ncpu': 8}, 64),      # the loader tunable raised it
    ({'hw_vmm_maxcpu': 4, 'hw_ncpu': 4}, 4),
    ({'hw_ncpu': 12}, 12),                          # no sysctl: the host's threads, the kernel's default
    ({'hw_vmm_maxcpu': 0, 'hw_ncpu': 12}, 12),
    ({'hw_vmm_maxcpu': 'x', 'hw_ncpu': 6}, 6),
])
def test_bhyve_limit_is_the_hypervisors(monkeypatch, values, expected):
    sysctls(monkeypatch, **values)
    assert bhyve_max_vcpus() == expected


def test_bhyve_limit_without_any_sysctl_is_at_least_one(monkeypatch):
    sysctls(monkeypatch)
    monkeypatch.setattr(vm_module.os, 'cpu_count', lambda: None)
    assert bhyve_max_vcpus() == 1
    monkeypatch.setattr(vm_module.os, 'cpu_count', lambda: 10)
    assert bhyve_max_vcpus() == 10


@pytest.mark.parametrize('arch', [None, 'amd64'])
def test_maximum_supported_vcpus_is_the_bhyve_limit(monkeypatch, arch):
    sysctls(monkeypatch, hw_vmm_maxcpu=40, hw_ncpu=40)
    assert VMService.maximum_supported_vcpus.wraps(object.__new__(VMService), arch) == 40


async def vcpu_errors(monkeypatch, limit, **cpu):
    """The messages __common_validation gives for the vcpus field on a host whose bhyve limit is `limit`."""
    sysctls(monkeypatch, hw_vmm_maxcpu=limit, hw_ncpu=limit)
    svc = object.__new__(VMService)

    async def call(method, *args):
        if method == 'vm.flags':
            return FLAGS
        if method == 'vm.maximum_supported_vcpus':
            return VMService.maximum_supported_vcpus.wraps(svc, *(args or (None,)))
        if method in ('vm.query', 'vm.device.query'):
            return []
        raise AssertionError(method)

    svc.middleware = SimpleNamespace(call=call)
    svc.validate_slots = lambda data: False
    verrors = ValidationErrors()
    data = {'vcpus': 1, 'cores': 1, 'threads': 1, 'bootloader': 'UEFI', 'devices': [], **cpu}
    await svc._VMService__common_validation(verrors, 'vm_create', data)
    return [error.errmsg for error in verrors.errors if error.attribute == 'vm_create.vcpus']


@pytest.mark.asyncio
@pytest.mark.parametrize('limit,cpu', [
    (48, {'vcpus': 24}),                                # more than 16 on a host that has them
    (48, {'vcpus': 2, 'cores': 12, 'threads': 2}),      # exactly the limit
    (48, {'vcpus': 16}),
    (4, {'vcpus': 4}),
    (4, {'vcpus': 1}),
])
async def test_a_bhyve_guest_within_the_hosts_limit_is_accepted(monkeypatch, limit, cpu):
    assert await vcpu_errors(monkeypatch, limit, **cpu) == []


@pytest.mark.asyncio
@pytest.mark.parametrize('limit,cpu,product', [
    (48, {'vcpus': 49}, 49),
    (48, {'vcpus': 5, 'cores': 5, 'threads': 2}, 50),
    (4, {'vcpus': 8}, 8),                               # 16 or fewer, but more than this host can run
    (16, {'vcpus': 17}, 17),
])
async def test_a_bhyve_guest_above_the_hosts_limit_is_refused_with_the_number(monkeypatch, limit, cpu, product):
    errors = await vcpu_errors(monkeypatch, limit, **cpu)
    assert len(errors) == 1
    assert f'at most {limit} virtual CPUs' in errors[0] and errors[0].endswith(f'is {product}.')
