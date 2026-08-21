import os

import pytest
import requests

from functions import failed, SSHConnectionError


def pytest_addoption(parser):
    group = parser.getgroup("truenas-safety", "TrueNAS API2 safety controls")
    group.addoption(
        "--run-nested-vm",
        action="store_true",
        default=False,
        help="collect the upstream bhyve-inside-bhyve module; excluded by default on VM targets",
    )
    group.addoption(
        "--no-abort-on-target-loss",
        action="store_true",
        default=False,
        help="continue after the appliance becomes unreachable",
    )


def pytest_ignore_collect(path, config):
    """Prevent the nested-VM module from executing import-time API mutations.

    Upstream test_540_vm.py creates a VM at module import. A skip marker is too
    late because pytest imports the module before applying it. The paired VM
    parity run therefore does not collect this one hardware-only module unless
    the operator explicitly opts in with --run-nested-vm.
    """
    return (
        os.path.basename(str(path)) == "test_540_vm.py"
        and not config.getoption("--run-nested-vm")
    )


def pytest_report_header(config):
    if not config.getoption("--run-nested-vm"):
        return "EXCLUDED (not counted): test_540_vm.py — nested-bhyve hardware test"


@pytest.fixture(autouse=True)
def fail_fixture():
    if failed[0] is not None:
        pytest.exit(failed[0], 1)


# Stop once the appliance is genuinely unreachable. This does not turn a
# failure into a pass: the triggering test remains failed, while later cascade
# noise is prevented. Authentication rejection is deliberately not target loss.
_TARGET_LOST = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    SSHConnectionError,
)


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when != "call" or not report.failed:
        return
    if item.config.getoption("--no-abort-on-target-loss"):
        return
    exc = getattr(call, "excinfo", None)
    if exc is not None and isinstance(exc.value, _TARGET_LOST):
        failed[0] = (
            f"target became unreachable during {item.nodeid}: "
            f"{type(exc.value).__name__}: {exc.value}. "
            "Aborting because every later result would be a cascade."
        )
