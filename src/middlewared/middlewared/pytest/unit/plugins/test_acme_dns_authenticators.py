import inspect
import subprocess
from unittest.mock import AsyncMock, Mock, patch

import pytest

from middlewared.plugins.acme_.dns_authenticators import (
    AUTHENTICATORS,
    SECRET_MASK,
    CloudflareAuthenticator,
    DigitalOceanAuthenticator,
    OVHAuthenticator,
    Route53Authenticator,
    ShellAuthenticator,
    mask_attributes,
)
from middlewared.plugins.acme_protocol import DNSAuthenticatorService
from middlewared.plugins.crypto import CertificateService
from middlewared.service import CallError


class Middleware(dict):

    def __init__(self):
        super().__init__()
        self.event_register = Mock()

    async def call(self, name, *args):
        result = self[name](*args)
        return await result if inspect.isawaitable(result) else result

    def call_sync(self, name, *args):
        return self[name](*args)

    async def run_in_thread(self, method, *args, **kwargs):
        return method(*args, **kwargs)


def test_provider_registry_contains_supported_authenticators():
    assert set(AUTHENTICATORS) == {'cloudflare', 'digitalocean', 'OVH', 'route53', 'shell'}


def test_public_schema_includes_field_names_and_secret_metadata():
    schemas = DNSAuthenticatorService(Middleware()).authenticator_schemas()
    cloudflare = next(schema for schema in schemas if schema['key'] == 'cloudflare')
    api_token = next(field for field in cloudflare['schema'] if field['_name_'] == 'api_token')

    assert api_token['_private_'] is True
    assert api_token['title'] == 'API Token'


@pytest.mark.parametrize('provider, attributes, secrets', [
    ('cloudflare', {'cloudflare_email': None, 'api_key': 'key', 'api_token': 'token'}, {'api_key', 'api_token'}),
    ('digitalocean', {'digitalocean_token': 'token'}, {'digitalocean_token'}),
    (
        'OVH',
        {
            'application_key': 'application-key',
            'application_secret': 'application-secret',
            'consumer_key': 'consumer-key',
            'endpoint': 'ovh-eu',
        },
        {'application_secret', 'consumer_key'},
    ),
    ('route53', {'access_key_id': 'access-key', 'secret_access_key': 'secret-key'}, {'secret_access_key'}),
    ('shell', {'script': '/mnt/tank/auth.sh', 'user': 'nobody', 'timeout': 60, 'delay': 60}, set()),
])
def test_secret_attributes_are_masked(provider, attributes, secrets):
    unmasked = attributes.copy()
    masked = mask_attributes(provider, attributes)

    assert attributes == unmasked
    for key in attributes:
        assert masked[key] == (SECRET_MASK if key in secrets else attributes[key])


@pytest.mark.asyncio
@pytest.mark.parametrize('attributes, valid', [
    ({'cloudflare_email': None, 'api_key': None, 'api_token': 'token'}, True),
    ({'cloudflare_email': 'admin@example.test', 'api_key': 'key', 'api_token': None}, True),
    ({'cloudflare_email': 'admin@example.test', 'api_key': 'key', 'api_token': 'token'}, False),
    ({'cloudflare_email': None, 'api_key': None, 'api_token': None}, False),
])
async def test_cloudflare_credential_modes(attributes, valid):
    verrors = await CloudflareAuthenticator.validate_credentials(None, attributes)
    assert bool(verrors) is not valid


def test_cloudflare_perform_and_cleanup_use_exact_record():
    authenticator = CloudflareAuthenticator(None, {
        'cloudflare_email': None,
        'api_key': None,
        'api_token': 'token',
    })
    authenticator.PROPAGATION_DELAY = 0
    client = Mock()
    client._find_zone_id.return_value = 'zone-id'
    client.cf.zones.dns_records.get.return_value = [{'id': 'record-id'}]
    authenticator._client = Mock(return_value=client)

    authenticator.perform('www.example.test', '_acme-challenge.www.example.test', 'validation')
    authenticator.cleanup('www.example.test', '_acme-challenge.www.example.test', 'validation')

    client.add_txt_record.assert_called_once_with(
        'www.example.test', '_acme-challenge.www.example.test', 'validation', 600,
    )
    client.cf.zones.dns_records.get.assert_called_once_with('zone-id', params={
        'type': 'TXT',
        'name': '_acme-challenge.www.example.test',
        'content': 'validation',
        'per_page': 1,
    })
    client.cf.zones.dns_records.delete.assert_called_once_with('zone-id', 'record-id')


def test_digitalocean_perform_and_cleanup_use_exact_record():
    authenticator = DigitalOceanAuthenticator(None, {'digitalocean_token': 'token'})
    authenticator.PROPAGATION_DELAY = 0
    client = Mock()
    domain = Mock()
    record = Mock()
    record.type = 'TXT'
    record.name = '_acme-challenge.www'
    record.data = 'validation'
    domain.get_records.return_value = [record]
    client._find_domain.return_value = domain
    client._compute_record_name.return_value = '_acme-challenge.www'
    authenticator._client = Mock(return_value=client)

    authenticator.perform('www.example.test', '_acme-challenge.www.example.test', 'validation')
    authenticator.cleanup('www.example.test', '_acme-challenge.www.example.test', 'validation')

    client.add_txt_record.assert_called_once_with(
        'www.example.test', '_acme-challenge.www.example.test', 'validation', 600,
    )
    record.destroy.assert_called_once_with()


def test_ovh_perform_and_cleanup_use_exact_record():
    authenticator = OVHAuthenticator(None, {
        'application_key': 'application-key',
        'application_secret': 'application-secret',
        'consumer_key': 'consumer-key',
        'endpoint': 'ovh-eu',
    })
    authenticator.PROPAGATION_DELAY = 0
    client = Mock()
    authenticator._client = Mock(return_value=client)

    authenticator.perform('www.example.test', '_acme-challenge.www.example.test', 'validation')
    authenticator.cleanup('www.example.test', '_acme-challenge.www.example.test', 'validation')

    client.add_txt_record.assert_called_once_with(
        'www.example.test', '_acme-challenge.www.example.test', 'validation',
    )
    client.del_txt_record.assert_called_once_with(
        'www.example.test', '_acme-challenge.www.example.test', 'validation',
    )


def test_route53_perform_and_cleanup_wait_for_changes():
    route53 = Mock()
    route53.get_paginator.return_value.paginate.return_value = [{
        'HostedZones': [{
            'Config': {'PrivateZone': False},
            'Name': 'example.test.',
            'Id': 'zone-id',
        }],
    }]
    route53.change_resource_record_sets.side_effect = [
        {'ChangeInfo': {'Id': 'create-id', 'Status': 'PENDING'}},
        {'ChangeInfo': {'Id': 'delete-id', 'Status': 'PENDING'}},
    ]
    route53.get_change.return_value = {'ChangeInfo': {'Status': 'INSYNC'}}

    with patch('middlewared.plugins.acme_.dns_authenticators.boto3.Session') as session:
        session.return_value.client.return_value = route53
        authenticator = Route53Authenticator(None, {
            'access_key_id': 'access-key',
            'secret_access_key': 'secret-key',
        })
        authenticator.perform('www.example.test', '_acme-challenge.www.example.test', 'validation')
        authenticator.cleanup('www.example.test', '_acme-challenge.www.example.test', 'validation')

    actions = [
        call.kwargs['ChangeBatch']['Changes'][0]['Action']
        for call in route53.change_resource_record_sets.call_args_list
    ]
    assert actions == ['UPSERT', 'DELETE']
    assert route53.get_change.call_count == 2


def test_shell_perform_and_cleanup_run_as_configured_user():
    attributes = {
        'script': '/mnt/tank/auth.sh',
        'user': 'acme',
        'timeout': 30,
        'delay': 10,
    }
    authenticator = ShellAuthenticator(None, attributes)
    authenticator.PROPAGATION_DELAY = 0

    with patch(
        'middlewared.plugins.acme_.dns_authenticators.run_command_with_user_context',
        return_value=subprocess.CompletedProcess('auth.sh', 0),
    ) as run:
        authenticator.perform('example.test', '_acme-challenge.example.test', 'validation')
        authenticator.cleanup('example.test', '_acme-challenge.example.test', 'validation')

    assert [call.args[0].split()[1] for call in run.call_args_list] == ['set', 'unset']
    assert all(call.args[1] == 'acme' for call in run.call_args_list)


def test_cleanup_failure_is_actionable_and_does_not_include_credentials():
    authenticator = CloudflareAuthenticator(None, {
        'cloudflare_email': None,
        'api_key': None,
        'api_token': 'private-token',
    })
    client = Mock()
    client._find_zone_id.side_effect = RuntimeError('provider refused deletion')
    authenticator._client = Mock(return_value=client)

    with pytest.raises(CallError, match='Failed to clean up cloudflare challenge') as error:
        authenticator.cleanup('example.test', '_acme-challenge.example.test', 'validation')

    assert 'private-token' not in str(error.value)


@pytest.mark.asyncio
async def test_masked_secret_is_preserved_on_update():
    middleware = Middleware()
    middleware['datastore.update'] = Mock()
    service = DNSAuthenticatorService(middleware)
    service.get_raw_instance = AsyncMock(return_value={
        'id': 1,
        'name': 'AWS',
        'authenticator': 'route53',
        'attributes': {
            'access_key_id': 'old-access-key',
            'secret_access_key': 'stored-secret',
        },
    })
    service.common_validation = AsyncMock()
    service._get_instance = AsyncMock(return_value={'id': 1})

    await service.do_update(1, {
        'attributes': {
            'access_key_id': 'new-access-key',
            'secret_access_key': SECRET_MASK,
        },
    })

    updated = middleware['datastore.update'].call_args.args[2]
    assert updated['attributes'] == {
        'access_key_id': 'new-access-key',
        'secret_access_key': 'stored-secret',
    }


def test_authorization_payload_is_queued_before_provider_call():
    middleware = Middleware()
    cleanup_payloads = []

    def fail_after_create(payload):
        assert cleanup_payloads == [payload]
        raise CallError('propagation check failed after record creation')

    middleware['acme.dns.authenticator.update_txt_record'] = Mock(side_effect=fail_after_create)
    service = CertificateService(middleware)
    challenge = Mock()
    challenge.typ = 'dns-01'
    challenge.json_dumps.return_value = '{"challenge": true}'
    challenge.response.return_value = 'response'
    authorization = Mock()
    authorization.body.identifier.value = 'example.test'
    authorization.body.challenges = [challenge]
    order = Mock(authorizations=[authorization])
    key = Mock()
    key.json_dumps.return_value = '{"key": true}'
    acme_client = Mock()
    job = Mock()

    with pytest.raises(CallError, match='propagation check failed'):
        service.handle_authorizations(
            job, 20, order, {'example.test': 4}, acme_client, key, cleanup_payloads,
        )

    assert cleanup_payloads == [{
        'authenticator': 4,
        'challenge': '{"challenge": true}',
        'domain': 'example.test',
        'key': '{"key": true}',
    }]
    acme_client.answer_challenge.assert_not_called()


def test_cleanup_attempts_every_queued_authorization_and_reports_failures():
    middleware = Middleware()

    def cleanup(payload):
        if payload['domain'] == 'first.example.test':
            raise CallError('provider refused deletion')

    middleware['acme.dns.authenticator.cleanup_txt_record'] = Mock(side_effect=cleanup)
    service = CertificateService(middleware)
    payloads = [
        {'domain': 'first.example.test'},
        {'domain': 'second.example.test'},
    ]

    cleanup_errors = service.cleanup_authorizations(payloads)

    assert middleware['acme.dns.authenticator.cleanup_txt_record'].call_count == 2
    assert cleanup_errors == ['first.example.test: [EFAULT] provider refused deletion']


def test_certificate_flow_cleans_records_after_validation_and_before_finalization():
    events = []
    middleware = Middleware()
    middleware['certificate.get_domain_names'] = Mock(return_value=['example.test'])
    middleware['acme.dns.authenticator.query'] = Mock(return_value=[{'id': 4}])
    middleware['cryptokey.normalize_san'] = Mock(return_value=[('DNS', 'example.test')])
    middleware['acme.dns.authenticator.update_txt_record'] = Mock(
        side_effect=lambda payload: events.append('set'),
    )
    middleware['acme.dns.authenticator.cleanup_txt_record'] = Mock(
        side_effect=lambda payload: events.append('unset'),
    )
    service = CertificateService(middleware)
    challenge = Mock()
    challenge.typ = 'dns-01'
    challenge.json_dumps.return_value = '{"challenge": true}'
    challenge.response.return_value = 'response'
    authorization = Mock()
    authorization.body.identifier.value = 'example.test'
    authorization.body.challenges = [challenge]
    order = Mock(authorizations=[authorization])
    key = Mock()
    key.json_dumps.return_value = '{"key": true}'
    acme_client = Mock()
    acme_client.new_order.return_value = order
    acme_client.answer_challenge.side_effect = lambda *args: events.append('answer') or True
    acme_client.poll_authorizations.side_effect = lambda *args: events.append('poll') or order
    final_order = Mock()
    acme_client.finalize_order.side_effect = lambda *args: events.append('finalize') or final_order
    service.get_acme_client_and_key = Mock(return_value=(acme_client, key))

    result = service.acme_issue_certificate(
        Mock(),
        20,
        {
            'acme_directory_uri': 'https://acme.example.test/directory',
            'dns_mapping': {'example.test': 4},
            'tos': True,
        },
        {'id': 1, 'CSR': 'certificate-request'},
    )

    assert result is final_order
    assert events == ['set', 'answer', 'poll', 'unset', 'finalize']


def test_certificate_flow_cleans_records_when_validation_fails():
    events = []
    middleware = Middleware()
    middleware['certificate.get_domain_names'] = Mock(return_value=['example.test'])
    middleware['acme.dns.authenticator.query'] = Mock(return_value=[{'id': 4}])
    middleware['cryptokey.normalize_san'] = Mock(return_value=[('DNS', 'example.test')])
    middleware['acme.dns.authenticator.update_txt_record'] = Mock(
        side_effect=lambda payload: events.append('set'),
    )
    middleware['acme.dns.authenticator.cleanup_txt_record'] = Mock(
        side_effect=lambda payload: events.append('unset'),
    )
    service = CertificateService(middleware)
    challenge = Mock()
    challenge.typ = 'dns-01'
    challenge.json_dumps.return_value = '{"challenge": true}'
    challenge.response.return_value = 'response'
    authorization = Mock()
    authorization.body.identifier.value = 'example.test'
    authorization.body.challenges = [challenge]
    order = Mock(authorizations=[authorization])
    key = Mock()
    key.json_dumps.return_value = '{"key": true}'
    acme_client = Mock()
    acme_client.new_order.return_value = order
    acme_client.answer_challenge.side_effect = lambda *args: events.append('answer') or True

    def fail_validation(*args):
        events.append('poll')
        raise CallError('validation failed')

    acme_client.poll_authorizations.side_effect = fail_validation
    service.get_acme_client_and_key = Mock(return_value=(acme_client, key))

    with pytest.raises(CallError, match='validation failed'):
        service.acme_issue_certificate(
            Mock(),
            20,
            {
                'acme_directory_uri': 'https://acme.example.test/directory',
                'dns_mapping': {'example.test': 4},
                'tos': True,
            },
            {'id': 1, 'CSR': 'certificate-request'},
        )

    assert events == ['set', 'answer', 'poll', 'unset']
    acme_client.finalize_order.assert_not_called()
