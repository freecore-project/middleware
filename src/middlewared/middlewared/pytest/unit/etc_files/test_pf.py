from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from middlewared.etc_files import pf
from middlewared.service_exception import CallError


class PFMiddleware:

    def call_sync(self, name, *args):
        if name == 'applications.config':
            return {'pool': 'tank'}
        if name == 'failover.licensed':
            return False
        if name == 'route.system_routes':
            return [{
                'network': '0.0.0.0',
                'netmask': '0.0.0.0',
                'gateway': '192.0.2.1',
                'interface': 'igb0',
            }]
        if name == 'interface.query':
            return [{
                'failover_virtual_aliases': [{'address': '192.0.2.10'}],
            }]
        if name == 'ssh.config':
            return {'tcpport': 22}
        if name == 'system.general.config':
            return {'ui_port': 80, 'ui_httpsport': 443}
        raise AssertionError(f'unexpected middleware call: {name!r} {args!r}')


class IPv6OnlyPFMiddleware(PFMiddleware):

    def call_sync(self, name, *args):
        if name == 'route.system_routes':
            return [{
                'network': '::',
                'netmask': '::',
                'gateway': '2001:db8::1',
                'interface': 'igb0',
            }]
        return super().call_sync(name, *args)


def result(returncode=0, stdout='', stderr=''):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_application_rules_add_only_cni_translation():
    rules = pf.build_rules(PFMiddleware(), applications=True, failover=False)

    assert 'v4egress_if = "igb0"' in rules
    assert 'table <cni-nat>' in rules
    assert 'nat on $v4egress_if inet from <cni-nat>' in rules
    assert 'rdr-anchor "cni-rdr/*"' in rules
    assert 'Failover management-access protection' not in rules
    assert 'block drop' not in rules


def test_application_rules_require_ipv4_egress_for_ipv4_container_subnet():
    with pytest.raises(CallError, match='IPv4 default-route'):
        pf.build_rules(IPv6OnlyPFMiddleware(), applications=True, failover=False)


def test_pf_rules_activate_only_after_prerequisites_are_staged(tmp_path):
    marker = tmp_path / 'pf-active'
    rules_file = tmp_path / 'pf.conf.block'
    load_rules = Mock()

    with (
        patch.object(pf, 'RUNTIME_PF_ACTIVE', str(marker)),
        patch.object(pf, 'PF_BLOCK_FILE', str(rules_file)),
        patch.object(pf, '_load_rules', load_rules),
    ):
        pf.render(None, PFMiddleware())
        load_rules.assert_not_called()

        marker.write_text('active\n')
        pf.render(None, PFMiddleware())

    load_rules.assert_called_once()
    assert load_rules.call_args.args[1] is True


def test_composite_rules_preserve_failover_management_protection():
    rules = pf.build_rules(PFMiddleware(), applications=True, failover=True)

    assert "ips = '{ 192.0.2.10 }'" in rules
    assert "ports = '{ 22, 80, 443 }'" in rules
    assert 'pass in quick proto tcp from any to any port $ports' in rules
    assert 'block drop in quick proto tcp from any to $ips' in rules
    assert rules.index('nat on $v4egress_if') < rules.index('pass in quick proto tcp')


def test_validation_failure_never_replaces_live_rules(tmp_path):
    rules_file = tmp_path / 'pf.conf.block'
    rules_file.write_text('prior rules\n')

    with (
        patch.object(pf, 'PF_BLOCK_FILE', str(rules_file)),
        patch.object(pf, '_run_pfctl', return_value=result(1, stderr='syntax error')) as run_pfctl,
        pytest.raises(CallError, match='failed validation'),
    ):
        pf._load_rules('invalid rules\n', enable=True)

    assert rules_file.read_text() == 'prior rules\n'
    run_pfctl.assert_called_once()


def test_load_failure_restores_file_and_active_rules(tmp_path):
    rules_file = tmp_path / 'pf.conf.block'
    rules_file.write_text('prior rules\n')

    with (
        patch.object(pf, 'PF_BLOCK_FILE', str(rules_file)),
        patch.object(pf, '_run_pfctl', side_effect=[
            result(),
            result(1, stderr='load failed'),
            result(),
        ]) as run_pfctl,
        pytest.raises(CallError, match='previous rules were restored'),
    ):
        pf._load_rules('new rules\n', enable=True)

    assert rules_file.read_text() == 'prior rules\n'
    assert run_pfctl.call_args_list[-1].args == ('-f', str(rules_file))


def test_enable_failure_restores_prior_rules(tmp_path):
    rules_file = tmp_path / 'pf.conf.block'
    rules_file.write_text('prior rules\n')

    with (
        patch.object(pf, 'PF_BLOCK_FILE', str(rules_file)),
        patch.object(pf, '_run_pfctl', side_effect=[
            result(),
            result(),
            result(stdout='Status: Disabled\n'),
            result(1, stderr='enable failed'),
            result(),
        ]),
        pytest.raises(CallError, match='previous rules were restored'),
    ):
        pf._load_rules('new rules\n', enable=True)

    assert rules_file.read_text() == 'prior rules\n'


def test_load_failure_without_prior_rules_reports_unrecoverable_state(tmp_path):
    rules_file = tmp_path / 'pf.conf.block'

    with (
        patch.object(pf, 'PF_BLOCK_FILE', str(rules_file)),
        patch.object(pf, '_run_pfctl', side_effect=[
            result(),
            result(1, stderr='load failed'),
        ]),
        pytest.raises(CallError, match='no prior rules file was available to reload'),
    ):
        pf._load_rules('new rules\n', enable=True)

    assert not rules_file.exists()


def test_pfctl_execution_errors_are_observable():
    with (
        patch.object(pf.subprocess, 'run', Mock(side_effect=OSError('missing pfctl'))),
        pytest.raises(CallError, match='missing pfctl'),
    ):
        pf._run_pfctl('-s', 'info')
