import hashlib
import json
import os
import shlex
import time
from urllib.parse import urlencode

import boto3
from botocore import exceptions as boto_exceptions
from certbot.plugins.dns_common import base_domain_name_guesses
from certbot_dns_cloudflare._internal.dns_cloudflare import _CloudflareClient
from certbot_dns_digitalocean._internal.dns_digitalocean import _DigitalOceanClient
import requests

from middlewared.async_validators import check_path_resides_within_volume
from middlewared.schema import Int, Str
from middlewared.service import CallError, ValidationErrors
from middlewared.utils.osc import run_command_with_user_context
from middlewared.validators import Range


SECRET_MASK = '********'


class DNSAuthenticator:

    NAME = None
    PROPAGATION_DELAY = 60
    SCHEMA = []
    SECRET_FIELDS = set()

    def __init__(self, middleware, attributes):
        self.middleware = middleware
        self.attributes = attributes

    @classmethod
    async def validate_credentials(cls, middleware, attributes):
        return ValidationErrors()

    def perform(self, domain, validation_name, validation_content):
        try:
            result = self._perform(domain, validation_name, validation_content)
        except CallError:
            raise
        except Exception as e:
            raise CallError(f'Failed to perform {self.NAME} challenge for {domain!r}: {e}')

        if self.PROPAGATION_DELAY:
            time.sleep(self.PROPAGATION_DELAY)
        return result

    def cleanup(self, domain, validation_name, validation_content):
        try:
            return self._cleanup(domain, validation_name, validation_content)
        except CallError:
            raise
        except Exception as e:
            raise CallError(f'Failed to clean up {self.NAME} challenge for {domain!r}: {e}')


class CloudflareAuthenticator(DNSAuthenticator):

    NAME = 'cloudflare'
    SCHEMA = [
        Str(
            'cloudflare_email', title='Cloudflare Email', null=True, default=None,
            description='Email address used with a legacy Cloudflare Global API Key.',
        ),
        Str(
            'api_key', title='Global API Key', null=True, default=None, private=True,
            description='Legacy Cloudflare Global API Key. Use together with Cloudflare Email.',
        ),
        Str(
            'api_token', title='API Token', null=True, default=None, private=True,
            description='Recommended scoped Cloudflare API token with Zone:DNS:Edit access.',
        ),
    ]
    SECRET_FIELDS = {'api_key', 'api_token'}

    @classmethod
    async def validate_credentials(cls, middleware, attributes):
        verrors = ValidationErrors()
        email = attributes.get('cloudflare_email')
        api_key = attributes.get('api_key')
        api_token = attributes.get('api_token')

        if api_token:
            if email:
                verrors.add(
                    'cloudflare_email',
                    'Cloudflare Email cannot be used together with an API Token.',
                )
            if api_key:
                verrors.add(
                    'api_key',
                    'Use either an API Token or Cloudflare Email plus Global API Key, not both.',
                )
        elif email or api_key:
            if not email:
                verrors.add('cloudflare_email', 'Cloudflare Email is required with a Global API Key.')
            if not api_key:
                verrors.add('api_key', 'Global API Key is required with Cloudflare Email.')
        else:
            verrors.add(
                'api_token',
                'Specify a scoped API Token, or Cloudflare Email plus Global API Key.',
            )

        return verrors

    def _client(self):
        if self.attributes.get('api_token'):
            return _CloudflareClient(api_token=self.attributes['api_token'])
        return _CloudflareClient(
            email=self.attributes['cloudflare_email'], api_key=self.attributes['api_key'],
        )

    def _perform(self, domain, validation_name, validation_content):
        self._client().add_txt_record(domain, validation_name, validation_content, 600)

    def _cleanup(self, domain, validation_name, validation_content):
        client = self._client()
        zone_id = client._find_zone_id(domain)
        records = client.cf.zones.dns_records.get(zone_id, params={
            'type': 'TXT',
            'name': validation_name,
            'content': validation_content,
            'per_page': 1,
        })
        if records:
            client.cf.zones.dns_records.delete(zone_id, records[0]['id'])


class DigitalOceanAuthenticator(DNSAuthenticator):

    NAME = 'digitalocean'
    SCHEMA = [
        Str(
            'digitalocean_token', title='DigitalOcean Token', required=True, empty=False, private=True,
            description='DigitalOcean API token with read and write access to the authoritative DNS zone.',
        ),
    ]
    SECRET_FIELDS = {'digitalocean_token'}

    def _client(self):
        return _DigitalOceanClient(self.attributes['digitalocean_token'])

    def _perform(self, domain, validation_name, validation_content):
        self._client().add_txt_record(domain, validation_name, validation_content, 600)

    def _cleanup(self, domain, validation_name, validation_content):
        client = self._client()
        digitalocean_domain = client._find_domain(domain)
        record_name = client._compute_record_name(digitalocean_domain, validation_name)
        for record in digitalocean_domain.get_records():
            if (
                record.type == 'TXT' and
                record.name == record_name and
                record.data == validation_content
            ):
                record.destroy()


OVH_ENDPOINTS = {
    'ovh-eu': 'https://eu.api.ovh.com/1.0',
    'ovh-ca': 'https://ca.api.ovh.com/1.0',
    'ovh-us': 'https://api.ovhcloud.com/1.0',
}


class _OVHClient:

    def __init__(self, endpoint, application_key, application_secret, consumer_key, ttl):
        self.endpoint_api = OVH_ENDPOINTS[endpoint]
        self.application_key = application_key
        self.application_secret = application_secret
        self.consumer_key = consumer_key
        self.ttl = ttl
        self.session = requests.Session()
        self._time_delta = None

    def _sync_time(self):
        if self._time_delta is None:
            response = self.session.get(f'{self.endpoint_api}/auth/time', timeout=30)
            response.raise_for_status()
            self._time_delta = response.json() - int(time.time())
        return self._time_delta

    def _request(self, method, path, data=None, params=None):
        url = self.endpoint_api + path
        body = json.dumps(data) if data is not None else ''
        timestamp = str(int(time.time()) + self._sync_time())
        signed_url = f'{url}?{urlencode(params)}' if params else url
        signature_payload = '+'.join([
            self.application_secret,
            self.consumer_key,
            method.upper(),
            signed_url,
            body,
            timestamp,
        ]).encode()
        headers = {
            'X-Ovh-Application': self.application_key,
            'X-Ovh-Consumer': self.consumer_key,
            'X-Ovh-Timestamp': timestamp,
            'X-Ovh-Signature': '$1$' + hashlib.sha1(signature_payload).hexdigest(),
        }
        if data is not None:
            headers['Content-Type'] = 'application/json'

        response = self.session.request(
            method, url, params=params, data=body, headers=headers, timeout=30,
        )
        response.raise_for_status()
        return response.json() if response.text else None

    def _find_zone(self, domain):
        available = set(self._request('GET', '/domain/zone') or [])
        for guess in base_domain_name_guesses(domain):
            if guess in available:
                return guess
        raise CallError(f'Unable to determine an OVH DNS zone for {domain!r}')

    @staticmethod
    def _relative_name(zone, fqdn):
        name = fqdn.rstrip('.').lower()
        suffix = '.' + zone.rstrip('.').lower()
        return name[:-len(suffix)] if name.endswith(suffix) else name

    def _find_record_ids(self, zone, sub_domain, content):
        record_ids = self._request(
            'GET', f'/domain/zone/{zone}/record',
            params={'fieldType': 'TXT', 'subDomain': sub_domain},
        ) or []
        return [
            record_id for record_id in record_ids
            if (self._request('GET', f'/domain/zone/{zone}/record/{record_id}') or {}).get('target') == content
        ]

    def add_txt_record(self, domain, validation_name, validation_content):
        zone = self._find_zone(domain)
        sub_domain = self._relative_name(zone, validation_name)
        if self._find_record_ids(zone, sub_domain, validation_content):
            return
        self._request('POST', f'/domain/zone/{zone}/record', data={
            'fieldType': 'TXT',
            'subDomain': sub_domain,
            'target': validation_content,
            'ttl': self.ttl,
        })
        self._request('POST', f'/domain/zone/{zone}/refresh')

    def del_txt_record(self, domain, validation_name, validation_content):
        zone = self._find_zone(domain)
        sub_domain = self._relative_name(zone, validation_name)
        for record_id in self._find_record_ids(zone, sub_domain, validation_content):
            self._request('DELETE', f'/domain/zone/{zone}/record/{record_id}')
        self._request('POST', f'/domain/zone/{zone}/refresh')


class OVHAuthenticator(DNSAuthenticator):

    NAME = 'OVH'
    SCHEMA = [
        Str('application_key', title='Application Key', required=True, empty=False),
        Str(
            'application_secret', title='Application Secret', required=True, empty=False, private=True,
        ),
        Str('consumer_key', title='Consumer Key', required=True, empty=False, private=True),
        Str(
            'endpoint', title='Endpoint', required=True, default='ovh-eu', enum=list(OVH_ENDPOINTS),
            description='OVHcloud API region.',
        ),
    ]
    SECRET_FIELDS = {'application_secret', 'consumer_key'}

    def _client(self):
        return _OVHClient(
            self.attributes['endpoint'],
            self.attributes['application_key'],
            self.attributes['application_secret'],
            self.attributes['consumer_key'],
            600,
        )

    def _perform(self, domain, validation_name, validation_content):
        self._client().add_txt_record(domain, validation_name, validation_content)

    def _cleanup(self, domain, validation_name, validation_content):
        self._client().del_txt_record(domain, validation_name, validation_content)


class Route53Authenticator(DNSAuthenticator):

    NAME = 'route53'
    PROPAGATION_DELAY = 0
    SCHEMA = [
        Str('access_key_id', title='Access ID Key', required=True, empty=False),
        Str(
            'secret_access_key', title='Secret Access Key', required=True, empty=False, private=True,
        ),
    ]
    SECRET_FIELDS = {'secret_access_key'}

    def __init__(self, middleware, attributes):
        super().__init__(middleware, attributes)
        self.client = boto3.Session(
            aws_access_key_id=attributes['access_key_id'],
            aws_secret_access_key=attributes['secret_access_key'],
        ).client('route53')

    def _find_zone_id(self, domain):
        target_labels = domain.rstrip('.').split('.')
        zones = []
        try:
            for page in self.client.get_paginator('list_hosted_zones').paginate():
                for zone in page['HostedZones']:
                    if zone['Config']['PrivateZone']:
                        continue
                    candidate_labels = zone['Name'].rstrip('.').split('.')
                    if candidate_labels == target_labels[-len(candidate_labels):]:
                        zones.append((zone['Name'], zone['Id']))
        except (boto_exceptions.BotoCoreError, boto_exceptions.ClientError) as e:
            raise CallError(f'Failed to list Route 53 hosted zones: {e}')

        if not zones:
            raise CallError(f'Unable to find a Route 53 hosted zone for {domain!r}')
        zones.sort(key=lambda zone: len(zone[0]), reverse=True)
        return zones[0][1]

    def _change(self, action, validation_name, validation_content):
        try:
            response = self.client.change_resource_record_sets(
                HostedZoneId=self._find_zone_id(validation_name),
                ChangeBatch={
                    'Comment': f'FreeCORE ACME DNS-01 {action}',
                    'Changes': [{
                        'Action': action,
                        'ResourceRecordSet': {
                            'Name': validation_name,
                            'Type': 'TXT',
                            'TTL': 10,
                            'ResourceRecords': [{'Value': f'"{validation_content}"'}],
                        },
                    }],
                },
            )
        except (boto_exceptions.BotoCoreError, boto_exceptions.ClientError) as e:
            raise CallError(f'Failed to {action.lower()} Route 53 TXT record: {e}')
        return response['ChangeInfo']

    def _wait(self, change):
        status = change.get('Status')
        for unused_n in range(120):
            try:
                response = self.client.get_change(Id=change['Id'])
            except (boto_exceptions.BotoCoreError, boto_exceptions.ClientError) as e:
                raise CallError(f'Failed to check Route 53 change status: {e}')
            status = response['ChangeInfo']['Status']
            if status == 'INSYNC':
                return
            time.sleep(5)
        raise CallError(f'Timed out waiting for Route 53 change; last status was {status!r}')

    def _perform(self, domain, validation_name, validation_content):
        change = self._change('UPSERT', validation_name, validation_content)
        self._wait(change)

    def _cleanup(self, domain, validation_name, validation_content):
        change = self._change('DELETE', validation_name, validation_content)
        self._wait(change)


class ShellAuthenticator(DNSAuthenticator):

    NAME = 'shell'
    SCHEMA = [
        Str(
            'script', title='Authentication Script', required=True, empty=False,
            description='Executable script stored inside a data-pool mount point.',
        ),
        Str('user', title='Running User', default='nobody', empty=False),
        Int('timeout', title='Script Timeout', default=60, validators=[Range(min=5)]),
        Int('delay', title='Propagation Delay', default=60, validators=[Range(min=10)]),
    ]

    def __init__(self, middleware, attributes):
        super().__init__(middleware, attributes)
        self.PROPAGATION_DELAY = attributes['delay']

    @classmethod
    async def validate_credentials(cls, middleware, attributes):
        verrors = ValidationErrors()
        script = attributes['script']
        user = attributes['user']

        try:
            await middleware.call('user.get_user_obj', {'username': user})
        except KeyError:
            verrors.add('user', f'Unable to locate user {user!r}.')

        await check_path_resides_within_volume(verrors, middleware, 'script', script)
        if not os.path.isfile(script):
            verrors.add('script', 'Script must be an existing regular file.')
        elif not verrors:
            command = f'test -x {shlex.quote(script)}'
            result = await middleware.run_in_thread(
                run_command_with_user_context, command, user, lambda line: None,
            )
            if result.returncode:
                verrors.add('script', f'User {user!r} cannot execute the script.')

        return verrors

    def _run(self, action, domain, validation_name, validation_content):
        command = ' '.join(shlex.quote(value) for value in [
            self.attributes['script'], action, domain, validation_name, validation_content,
        ])
        deadline = time.monotonic() + self.attributes['timeout']
        result = run_command_with_user_context(
            command,
            self.attributes['user'],
            lambda line: None,
            abort=lambda: time.monotonic() >= deadline,
        )
        if result.returncode:
            if time.monotonic() >= deadline:
                raise CallError(f'ACME shell authenticator timed out during {action!r}.')
            raise CallError(
                f'ACME shell authenticator exited with status {result.returncode} during {action!r}.',
            )

    def _perform(self, domain, validation_name, validation_content):
        self._run('set', domain, validation_name, validation_content)

    def _cleanup(self, domain, validation_name, validation_content):
        self._run('unset', domain, validation_name, validation_content)


AUTHENTICATORS = {
    authenticator.NAME: authenticator
    for authenticator in [
        CloudflareAuthenticator,
        DigitalOceanAuthenticator,
        OVHAuthenticator,
        Route53Authenticator,
        ShellAuthenticator,
    ]
}


def get_authenticator(name):
    try:
        return AUTHENTICATORS[name]
    except KeyError:
        raise CallError(f'Unable to locate {name!r} ACME DNS authenticator.')


def mask_attributes(name, attributes):
    result = attributes.copy()
    for field in get_authenticator(name).SECRET_FIELDS:
        if result.get(field):
            result[field] = SECRET_MASK
    return result
