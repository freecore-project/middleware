import josepy as jose
import json
import requests

from middlewared.schema import Bool, Dict, Int, Str, ValidationErrors
from middlewared.service import accepts, CallError, CRUDService, private
from middlewared.plugins.acme_.dns_authenticators import (
    AUTHENTICATORS,
    SECRET_MASK,
    get_authenticator,
    mask_attributes,
)
import middlewared.sqlalchemy as sa
from middlewared.validators import validate_attributes

from acme import client, messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


# TODO: See what can be done to respect rate limits


class ACMERegistrationModel(sa.Model):
    __tablename__ = 'system_acmeregistration'

    id = sa.Column(sa.Integer(), primary_key=True)
    uri = sa.Column(sa.String(200))
    directory = sa.Column(sa.String(200))
    tos = sa.Column(sa.String(200))
    new_account_uri = sa.Column(sa.String(200))
    new_nonce_uri = sa.Column(sa.String(200))
    new_order_uri = sa.Column(sa.String(200))
    revoke_cert_uri = sa.Column(sa.String(200))


class ACMERegistrationBodyModel(sa.Model):
    __tablename__ = 'system_acmeregistrationbody'

    id = sa.Column(sa.Integer(), primary_key=True)
    contact = sa.Column(sa.String(254))
    status = sa.Column(sa.String(10))
    key = sa.Column(sa.Text())
    acme_id = sa.Column(sa.ForeignKey('system_acmeregistration.id'), index=True)


class ACMERegistrationService(CRUDService):

    class Config:
        datastore = 'system.acmeregistration'
        datastore_extend = 'acme.registration.register_extend'
        namespace = 'acme.registration'
        private = True

    @private
    async def register_extend(self, data):
        body = await self.middleware.call(
            'datastore.query', 'system.acmeregistrationbody', [['acme', '=', data['id']]],
        )
        # A create interrupted between the two inserts leaves a registration with no body.
        # Report that as an empty body rather than raising, so a caller can recognise the
        # registration as unusable and discard it.
        data['body'] = {key: value for key, value in body[0].items() if key != 'acme'} if body else {}
        return data

    @private
    def get_directory(self, acme_directory_uri):
        try:
            acme_directory_uri = acme_directory_uri.rstrip('/')
            response = requests.get(acme_directory_uri).json()
            return messages.Directory({
                key: response[key] for key in ['newAccount', 'newNonce', 'newOrder', 'revokeCert']
            })
        except (requests.ConnectionError, requests.Timeout, json.JSONDecodeError, KeyError) as e:
            raise CallError(f'Unable to retrieve directory : {e}')

    @accepts(
        Dict(
            'acme_registration_create',
            Bool('tos', default=False),
            Dict(
                'JWK_create',
                Int('key_size', default=2048),
                Int('public_exponent', default=65537)
            ),
            Str('acme_directory_uri', required=True),
        )
    )
    def do_create(self, data):
        """
        Register with ACME Server

        Create a regisration for a specific ACME Server registering root user with it

        `acme_directory_uri` is a directory endpoint for any ACME Server

        .. examples(websocket)::

          Register with ACME Server

            :::javascript
            {
                "id": "6841f242-840a-11e6-a437-00e04d680384",
                "msg": "method",
                "method": "acme.registration.create",
                "params": [{
                    "tos": true,
                    "acme_directory_uri": "https://acme-staging-v02.api.letsencrypt.org/directory"
                    "JWK_create": {
                        "key_size": 2048,
                        "public_exponent": 65537
                    }
                }]
            }
        """
        # STEPS FOR CREATION
        # 1) CREATE KEY
        # 2) REGISTER CLIENT
        # 3) SAVE REGISTRATION OBJECT
        # 4) SAVE REGISTRATION BODY

        verrors = ValidationErrors()

        directory = self.get_directory(data['acme_directory_uri'])
        if not isinstance(directory, messages.Directory):
            verrors.add(
                'acme_registration_create.acme_directory_uri',
                f'System was unable to retrieve the directory with the specified acme_directory_uri: {directory}'
            )

        # Normalizing uri after directory call as let's encrypt staging api
        # does not accept a trailing slash right now
        data['acme_directory_uri'] += '/' if data['acme_directory_uri'][-1] != '/' else ''

        if not data['tos']:
            verrors.add(
                'acme_registration_create.tos',
                'Please agree to the terms of service'
            )

        # For now we assume that only root is responsible for certs issued under ACME protocol
        email = (self.middleware.call_sync('user.query', [['uid', '=', 0]]))[0]['email']
        if not email:
            raise CallError(
                'Please specify root email address which will be used with the ACME server'
            )

        existing = self.middleware.call_sync(
            'acme.registration.query', [['directory', '=', data['acme_directory_uri']]]
        )
        if existing and existing[0]['body']:
            verrors.add(
                'acme_registration_create.acme_directory_uri',
                'A registration with the specified directory uri already exists'
            )

        if verrors:
            raise verrors

        key = jose.JWKRSA(key=rsa.generate_private_key(
            public_exponent=data['JWK_create']['public_exponent'],
            key_size=data['JWK_create']['key_size'],
            backend=default_backend()
        ))
        acme_client = client.ClientV2(directory, client.ClientNetwork(key))
        register = acme_client.new_account(
            messages.NewRegistration.from_data(
                email=email,
                terms_of_service_agreed=True
            )
        )
        # We have registered with the acme server

        # Save registration object
        registration = {
            'uri': register.uri,
            'tos': register.terms_of_service,
            'new_account_uri': directory.newAccount,
            'new_nonce_uri': directory.newNonce,
            'new_order_uri': directory.newOrder,
            'revoke_cert_uri': directory.revokeCert,
            'directory': data['acme_directory_uri']
        }
        if existing:
            # Repairing a registration left bodyless by an interrupted create. Reuse the
            # row rather than replacing it: certificates carry a foreign key to it, so a
            # delete is refused outright once anything has been issued.
            registration_id = existing[0]['id']
            self.middleware.call_sync(
                'datastore.update', self._config.datastore, registration_id, registration,
            )
        else:
            registration_id = self.middleware.call_sync(
                'datastore.insert', self._config.datastore, registration,
            )

        # Save registration body
        try:
            self.middleware.call_sync(
                'datastore.insert',
                'system.acmeregistrationbody',
                {
                    # An ACME server is not obliged to echo the contact back, and Let's
                    # Encrypt no longer does - it returns an empty contact list. An absent
                    # contact is not an error, and must not abort a valid registration.
                    'contact': register.body.contact[0] if register.body.contact else '',
                    'status': register.body.status,
                    'key': key.json_dumps(),
                    'acme': registration_id
                }
            )
        except Exception:
            if not existing:
                # A registration row is unusable without its body and no public API can
                # remove it, so leaving a fresh one behind strands every later issuance
                # against this directory. Only roll back what this call inserted.
                self.middleware.call_sync('datastore.delete', self._config.datastore, registration_id)
            raise

        return self.middleware.call_sync(f'{self._config.namespace}._get_instance', registration_id)


class ACMEDNSAuthenticatorModel(sa.Model):
    __tablename__ = 'system_acmednsauthenticator'

    id = sa.Column(sa.Integer(), primary_key=True)
    authenticator = sa.Column(sa.String(64))
    name = sa.Column(sa.String(64))
    attributes = sa.Column(sa.JSON(encrypted=True))


class DNSAuthenticatorService(CRUDService):

    class Config:
        namespace = 'acme.dns.authenticator'
        datastore = 'system.acmednsauthenticator'
        datastore_extend = 'acme.dns.authenticator.extend'

    def __init__(self, *args, **kwargs):
        super(DNSAuthenticatorService, self).__init__(*args, **kwargs)
        self.schemas = DNSAuthenticatorService.initialize_authenticator_schemas()

    @accepts()
    def authenticator_schemas(self):
        """
        Get the schemas for all DNS providers we support for ACME DNS Challenge and the respective attributes
        required for connecting to them while validating a DNS Challenge
        """
        return [
            {
                'schema': [
                    dict(v.to_json_schema(), _name_=v.name, _private_=v.private)
                    for v in value
                ],
                'key': key,
            }
            for key, value in self.schemas.items()
        ]

    @staticmethod
    @private
    def initialize_authenticator_schemas():
        return {
            name: authenticator.SCHEMA
            for name, authenticator in AUTHENTICATORS.items()
        }

    @private
    async def common_validation(self, data, schema_name, id=None):
        verrors = ValidationErrors()

        await self._ensure_unique(verrors, schema_name, 'name', data['name'], id)

        if data['authenticator'] not in self.schemas:
            verrors.add(
                f'{schema_name}.authenticator',
                f'System does not support {data["authenticator"]} as an Authenticator'
            )
        else:
            attributes_verrors = validate_attributes(self.schemas[data['authenticator']], data)
            verrors.add_child(f'{schema_name}.attributes', attributes_verrors)
            if not attributes_verrors:
                credentials_verrors = await get_authenticator(data['authenticator']).validate_credentials(
                    self.middleware, data['attributes'],
                )
                verrors.add_child(f'{schema_name}.attributes', credentials_verrors)

        if verrors:
            raise verrors

    @private
    async def extend(self, data):
        data['attributes'] = mask_attributes(data['authenticator'], data['attributes'])
        return data

    @private
    async def get_raw_instance(self, id):
        return await self.middleware.call(
            'datastore.query', self._config.datastore,
            [['id', '=', id]], {'get': True},
        )

    @accepts(
        Dict(
            'dns_authenticator_create',
            Str('authenticator', required=True),
            Str('name', required=True),
            Dict('attributes', additional_attrs=True, required=True)
        )
    )
    async def do_create(self, data):
        """
        Create a DNS Authenticator

        Create a specific DNS Authenticator containing required authentication details for the said
        provider to successfully connect with it

        .. examples(websocket)::

          Create a DNS Authenticator for Route53

            :::javascript
            {
                "id": "6841f242-840a-11e6-a437-00e04d680384",
                "msg": "method",
                "method": "acme.dns.authenticator.create",
                "params": [{
                    "name": "route53_authenticator",
                    "authenticator": "route53",
                    "attributes": {
                        "access_key_id": "AQX13",
                        "secret_access_key": "JKW90"
                    }
                }]
            }
        """
        await self.common_validation(data, 'dns_authenticator_create')

        id = await self.middleware.call(
            'datastore.insert',
            self._config.datastore,
            data,
        )

        return await self._get_instance(id)

    @accepts(
        Int('id'),
        Dict(
            'dns_authenticator_update',
            Str('name'),
            Dict('attributes', additional_attrs=True)
        )
    )
    async def do_update(self, id, data):
        """
        Update DNS Authenticator of `id`

        .. examples(websocket)::

          Update a DNS Authenticator of `id`

            :::javascript
            {
                "id": "6841f242-840a-11e6-a437-00e04d680384",
                "msg": "method",
                "method": "acme.dns.authenticator.update",
                "params": [
                    1,
                    {
                        "name": "route53_authenticator",
                        "attributes": {
                            "access_key_id": "AQX13",
                            "secret_access_key": "JKW90"
                        }
                    }
                ]
            }
        """
        old = await self.get_raw_instance(id)
        new = old.copy()
        new.update({key: value for key, value in data.items() if key != 'attributes'})

        if 'attributes' in data:
            authenticator = get_authenticator(old['authenticator'])
            attributes = old['attributes'].copy()
            for key, value in data['attributes'].items():
                if key in authenticator.SECRET_FIELDS and value == SECRET_MASK:
                    continue
                attributes[key] = value
            new['attributes'] = attributes

        await self.common_validation(new, 'dns_authenticator_update', id)

        await self.middleware.call(
            'datastore.update',
            self._config.datastore,
            id,
            new
        )

        return await self._get_instance(id)

    @accepts(
        Int('id', required=True)
    )
    async def do_delete(self, id):
        """
        Delete DNS Authenticator of `id`

        .. examples(websocket)::

          Delete a DNS Authenticator of `id`

            :::javascript
            {
                "id": "6841f242-840a-11e6-a437-00e04d680384",
                "msg": "method",
                "method": "acme.dns.authenticator.delete",
                "params": [
                    1
                ]
            }
        """
        await self.middleware.call('certificate.delete_domains_authenticator', id)

        return await self.middleware.call(
            'datastore.delete',
            self._config.datastore,
            id
        )

    @accepts(
        Dict(
            'update_txt_record',
            Int('authenticator', required=True),
            Str('key', required=True, max_length=None),
            Str('domain', required=True),
            Str('challenge', required=True, max_length=None),
        )
    )
    @private
    def update_txt_record(self, data):
        authenticator = self.middleware.call_sync(
            'datastore.query', self._config.datastore,
            [['id', '=', data['authenticator']]], {'get': True},
        )
        domain, validation_name, validation_content = self.challenge_record(data)
        return get_authenticator(authenticator['authenticator'])(
            self.middleware, authenticator['attributes'],
        ).perform(domain, validation_name, validation_content)

    @accepts(
        Dict(
            'cleanup_txt_record',
            Int('authenticator', required=True),
            Str('key', required=True, max_length=None),
            Str('domain', required=True),
            Str('challenge', required=True, max_length=None),
        )
    )
    @private
    def cleanup_txt_record(self, data):
        authenticator = self.middleware.call_sync(
            'datastore.query', self._config.datastore,
            [['id', '=', data['authenticator']]], {'get': True},
        )
        domain, validation_name, validation_content = self.challenge_record(data)
        return get_authenticator(authenticator['authenticator'])(
            self.middleware, authenticator['attributes'],
        ).cleanup(domain, validation_name, validation_content)

    @staticmethod
    @private
    def challenge_record(data):
        challenge = messages.ChallengeBody.from_json(json.loads(data['challenge']))
        key = jose.JWKRSA.fields_from_json(json.loads(data['key']))
        return (
            data['domain'],
            challenge.validation_domain_name(data['domain']),
            challenge.validation(key),
        )
