import json
import time
import urllib.parse
from datetime import datetime

from middlewared.schema import Bool, Dict, Int, Str, accepts
from middlewared.service import CallError, ConfigService, no_auth_required, pass_app
import middlewared.sqlalchemy as sa

try:
    from webauthn import (
        base64url_to_bytes,
        generate_authentication_options,
        generate_registration_options,
        options_to_json,
        verify_authentication_response,
        verify_registration_response,
    )
    from webauthn.helpers import bytes_to_base64url
    from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        UserVerificationRequirement,
    )
    HAS_WEBAUTHN = True
except ImportError:
    # A missing py-webauthn package must degrade to "ceremonies unavailable",
    # never take middlewared down at plugin import time.
    HAS_WEBAUTHN = False

# How long a challenge issued by *_begin stays valid for its websocket session.
CHALLENGE_TTL = 120


class WebAuthnModel(sa.Model):
    __tablename__ = 'system_webauthn'

    id = sa.Column(sa.Integer(), primary_key=True)
    enabled = sa.Column(sa.Boolean(), default=False)


class WebAuthnCredentialModel(sa.Model):
    __tablename__ = 'system_webauthncredential'

    id = sa.Column(sa.Integer(), primary_key=True)
    name = sa.Column(sa.String(64))
    credential_id = sa.Column(sa.Text())
    public_key = sa.Column(sa.Text())
    sign_count = sa.Column(sa.Integer(), default=0)
    rp_id = sa.Column(sa.String(255))
    created_at = sa.Column(sa.DateTime())
    last_used = sa.Column(sa.DateTime(), nullable=True)


class WebAuthnService(ConfigService):
    """
    WebAuthn (FIDO2) hardware security keys as a second factor for web UI login.

    Challenge state lives in-process, keyed by the websocket session id: each
    `*_begin` call issues a challenge for that connection only, and the matching
    verify consumes it (single use, `CHALLENGE_TTL` seconds).
    """

    class Config:
        datastore = 'system.webauthn'
        namespace = 'auth.webauthn'

    _ceremonies = {}

    @accepts(
        Dict(
            'auth_webauthn_update',
            Bool('enabled'),
            update=True,
        )
    )
    async def do_update(self, data):
        """
        Update WebAuthn configuration.

        Enabling requires at least one enrolled security key. If all keys are
        lost, disable from the local console:
        `midclt call auth.webauthn.update '{"enabled": false}'`
        """
        config = await self.config()
        config.update(data)

        if config['enabled']:
            # TOTP is the DNS-independent fallback: browsers refuse WebAuthn on
            # IP-address origins, so a reachable second factor must always exist.
            # The reverse guard lives in auth.twofactor.update.
            if not (await self.middleware.call('auth.twofactor.config'))['enabled']:
                raise CallError(
                    'Enable Two-Factor (TOTP) authentication first. It is the fallback login '
                    'path when security keys are unavailable, e.g. when the UI is reached by '
                    'IP address (WebAuthn only works on DNS-name origins).'
                )
            if not await self.middleware.call(
                'datastore.query', 'system.webauthncredential', [], {'count': True}
            ):
                raise CallError('Enroll at least one security key before enabling WebAuthn.')

        await self.middleware.call(
            'datastore.update',
            self._config.datastore,
            config['id'],
            config,
        )

        return await self.config()

    @no_auth_required
    @accepts()
    async def status(self):
        """
        Returns true if WebAuthn is enforced for web UI login. Available before
        authentication so the signin page can decide whether to run the
        security-key ceremony.
        """
        return (await self.config())['enabled']

    @accepts()
    async def credentials(self):
        """
        List enrolled security keys (public metadata only).
        """
        return [
            {k: v for k, v in cred.items() if k != 'public_key'}
            for cred in await self.middleware.call('datastore.query', 'system.webauthncredential')
        ]

    @accepts(Int('id'))
    async def delete_credential(self, oid):
        """
        Remove an enrolled security key. The last remaining key cannot be
        removed while WebAuthn is enabled — disable WebAuthn first.
        """
        if (await self.config())['enabled'] and await self.middleware.call(
            'datastore.query', 'system.webauthncredential', [], {'count': True}
        ) <= 1:
            raise CallError(
                'Cannot remove the last security key while WebAuthn is enabled. Disable WebAuthn first.'
            )
        return await self.middleware.call('datastore.delete', 'system.webauthncredential', oid)

    @accepts(Str('name', max_length=64))
    @pass_app()
    def register_begin(self, app, name):
        """
        Start enrolling a new security key named `name`. Returns WebAuthn
        creation options to pass to `navigator.credentials.create()`.
        """
        self._require_lib()
        name = (name or '').strip()
        if not name:
            raise CallError('Provide a name for the security key.')

        creds = self.middleware.call_sync('datastore.query', 'system.webauthncredential')
        if any(c['name'] == name for c in creds):
            raise CallError(f'A security key named {name!r} is already enrolled.')

        origin, rp_id = self._request_origin(app)
        options = generate_registration_options(
            rp_id=rp_id,
            rp_name='FreeCORE',
            user_name='root',
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(c['credential_id']))
                for c in creds
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )
        self._put_ceremony(app, 'register', {
            'challenge': options.challenge,
            'origin': origin,
            'rp_id': rp_id,
            'name': name,
        })
        return json.loads(options_to_json(options))

    @accepts(Str('credential', max_length=16384))
    @pass_app()
    def register_complete(self, app, credential):
        """
        Finish enrolling a security key. `credential` is the JSON-serialized
        result of `navigator.credentials.create()`.
        """
        self._require_lib()
        state = self._pop_ceremony(app, 'register')
        if state is None:
            raise CallError('No security key registration in progress (or it expired) — start again.')

        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=state['challenge'],
                expected_rp_id=state['rp_id'],
                expected_origin=state['origin'],
                require_user_verification=False,
            )
        except InvalidRegistrationResponse as e:
            raise CallError(f'Security key registration failed: {e}')

        credential_id = bytes_to_base64url(verified.credential_id)
        if self.middleware.call_sync(
            'datastore.query', 'system.webauthncredential', [('credential_id', '=', credential_id)]
        ):
            raise CallError('This security key is already enrolled.')

        pk = self.middleware.call_sync('datastore.insert', 'system.webauthncredential', {
            'name': state['name'],
            'credential_id': credential_id,
            'public_key': bytes_to_base64url(verified.credential_public_key),
            'sign_count': verified.sign_count,
            'rp_id': state['rp_id'],
            'created_at': datetime.utcnow(),
            'last_used': None,
        })
        return {'id': pk, 'name': state['name']}

    @no_auth_required
    @accepts()
    @pass_app()
    def login_begin(self, app):
        """
        Start a security-key login. Returns WebAuthn request options to pass
        to `navigator.credentials.get()`.
        """
        self._require_lib()
        if not self.middleware.call_sync('auth.webauthn.config')['enabled']:
            raise CallError('WebAuthn is not enabled.')

        creds = self.middleware.call_sync('datastore.query', 'system.webauthncredential')
        if not creds:
            raise CallError('No security keys are enrolled.')

        origin, rp_id = self._request_origin(app)
        options = generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(c['credential_id']))
                for c in creds
            ],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        self._put_ceremony(app, 'login', {
            'challenge': options.challenge,
            'origin': origin,
            'rp_id': rp_id,
        })
        return json.loads(options_to_json(options))

    @no_auth_required
    @accepts(Str('username'), Str('password'), Str('credential', max_length=16384))
    @pass_app()
    def login(self, app, username, password, credential):
        """
        Authenticate session using username, password and a security-key
        assertion (the JSON-serialized result of `navigator.credentials.get()`
        for the options issued by `auth.webauthn.login_begin`).
        """
        self._require_lib()
        state = self._pop_ceremony(app, 'login')

        valid = self.middleware.call_sync('auth.check_user', username, password)
        # Like auth.login's OTP handling: always evaluate the second factor
        # regardless of the password result, to avoid a timing oracle.
        valid &= self._verify_assertion(state, credential)

        if valid:
            # Imported here so plugin load order can never matter.
            from middlewared.plugins.auth import AuthService, LoginPasswordSessionManagerCredentials
            AuthService.session_manager.login(app, LoginPasswordSessionManagerCredentials())
        return valid

    def _verify_assertion(self, state, credential):
        if state is None:
            return False

        try:
            parsed = json.loads(credential)
            asserted_id = parsed.get('rawId') or parsed.get('id')
        except (ValueError, AttributeError):
            return False
        if not asserted_id:
            return False

        rows = self.middleware.call_sync(
            'datastore.query', 'system.webauthncredential', [('credential_id', '=', asserted_id)]
        )
        if not rows:
            return False
        row = rows[0]

        try:
            verified = verify_authentication_response(
                credential=credential,
                expected_challenge=state['challenge'],
                expected_rp_id=state['rp_id'],
                expected_origin=state['origin'],
                credential_public_key=base64url_to_bytes(row['public_key']),
                credential_current_sign_count=row['sign_count'],
                require_user_verification=False,
            )
        except InvalidAuthenticationResponse:
            return False

        self.middleware.call_sync('datastore.update', 'system.webauthncredential', row['id'], {
            'sign_count': verified.new_sign_count,
            'last_used': datetime.utcnow(),
        })
        return True

    def _request_origin(self, app):
        # The nginx /websocket location does not forward Host (middlewared sees
        # 127.0.0.1:6000), but the browser's Origin header passes through — and
        # Origin is what the authenticator binds anyway. RP ID derives from it.
        origin = app.request.headers.get('Origin', '')
        parsed = urllib.parse.urlsplit(origin)
        if parsed.scheme != 'https' or not parsed.hostname:
            raise CallError(
                'WebAuthn requires accessing the web UI over https:// with a DNS '
                f'hostname (connection origin: {origin or "unknown"!r}).'
            )
        return origin, parsed.hostname

    def _require_lib(self):
        if not HAS_WEBAUTHN:
            raise CallError('py-webauthn is not installed.')

    def _put_ceremony(self, app, purpose, state):
        self._prune()
        state['deadline'] = time.monotonic() + CHALLENGE_TTL
        self._ceremonies[(app.session_id, purpose)] = state

    def _pop_ceremony(self, app, purpose):
        self._prune()
        return self._ceremonies.pop((app.session_id, purpose), None)

    def _prune(self):
        now = time.monotonic()
        for key in [k for k, v in self._ceremonies.items() if v['deadline'] < now]:
            self._ceremonies.pop(key, None)
