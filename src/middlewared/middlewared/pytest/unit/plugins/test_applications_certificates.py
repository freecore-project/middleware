"""the internal development record: system certificates mounted into an application.

The load-bearing rules: a key is never written where it can be read by the wrong user or
kept on the pool; a record that travels with an exported pool cannot bind to a different
certificate than the one it named; and a renewal is detected from the mounted content, so a
second pass restarts nothing.
"""
import contextlib
import copy
import datetime
import errno
import json
import os
import stat
from unittest.mock import AsyncMock, Mock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from middlewared import service as service_module
from middlewared.plugins.applications_ import certificates as app_certificates
from middlewared.plugins.applications_.reconfigure import (
    ReconfigureError,
    bind_reconfigure,
    anything_changed,
)
from middlewared.plugins.applications_.utils import podman_create_args, public_record
from middlewared.plugins.applications_catalog_freebsd import CATALOG_INSTALL_SCHEMA
from middlewared.plugins.applications_freebsd import ApplicationsService
from middlewared.service_exception import CallError, ValidationErrors

LEAF = '-----BEGIN CERTIFICATE-----\nbGVhZg==\n-----END CERTIFICATE-----'
INTERMEDIATE = '-----BEGIN CERTIFICATE-----\naW50\n-----END CERTIFICATE-----'
# the internal development record: generated per run, so the source carries no private-key block.
KEY = ec.generate_private_key(ec.SECP256R1()).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
).decode().strip()


def entry(**overrides):
    base = {
        'id': 7,
        'name': 'wildcard.example',
        'fingerprint': 'AA:BB',
        'target': '/certs',
        'restart_on_change': True,
        'uid': None,
        'gid': None,
    }
    base.update(overrides)
    return base


def record(**overrides):
    base = {
        'name': 'demo',
        'container_name': 'freecore-app-demo',
        'image': 'registry.example/demo:1',
        'restart_policy': 'always',
        'annotations': [],
        'environment': [],
        'ports': [],
        'volumes': [],
        'labels': [],
        'certificates': [],
    }
    base.update(overrides)
    return base


def certificate(chain=(LEAF, INTERMEDIATE), key=KEY):
    return {'id': 7, 'name': 'wildcard.example', 'fingerprint': 'AA:BB',
            'chain_list': list(chain), 'privatekey': key}


# -- the file set --------------------------------------------------------------------------

def test_the_certbot_layout_is_what_an_application_finds():
    files = app_certificates.rendered_files(certificate())

    assert set(files) == set(app_certificates.FILE_NAMES)
    assert files['cert.pem'] == LEAF + '\n'
    assert files['chain.pem'] == INTERMEDIATE + '\n'
    # byte-for-byte the host's own <name>.crt: '\n'.join(chain_list)
    assert files['fullchain.pem'] == '\n'.join((LEAF, INTERMEDIATE)) + '\n'
    assert files['privkey.pem'] == KEY + '\n'


def test_a_certificate_with_no_intermediate_still_gets_an_empty_chain_file():
    files = app_certificates.rendered_files(certificate(chain=(LEAF,)))

    assert files['chain.pem'] == ''
    assert files['cert.pem'] == files['fullchain.pem']


def test_a_certificate_without_a_key_or_a_chain_cannot_be_mounted():
    with pytest.raises(app_certificates.CertificateMountError):
        app_certificates.rendered_files(certificate(key=''))
    with pytest.raises(app_certificates.CertificateMountError):
        app_certificates.rendered_files(certificate(chain=()))
    with pytest.raises(app_certificates.CertificateMountError):
        app_certificates.rendered_files(certificate(chain=('not a pem',)))


# -- ownership -----------------------------------------------------------------------------

def test_the_files_belong_to_the_uid_the_image_runs_as():
    assert app_certificates.entry_owner(entry(), (1000, 1000)) == (1000, 1000)


def test_an_entry_overrides_the_images_uid_and_gid_separately():
    assert app_certificates.entry_owner(entry(uid=568), (1000, 1000)) == (568, 1000)
    assert app_certificates.entry_owner(entry(gid=568), (1000, 1000)) == (1000, 568)


def test_an_image_that_declares_nothing_leaves_the_files_to_root():
    assert app_certificates.entry_owner(entry(), None) == (0, 0)


# -- the target rules ----------------------------------------------------------------------

def test_a_target_must_be_an_absolute_normalized_directory():
    for bad in ('certs', '/', '/certs/', '/certs/../etc', '/certs:x'):
        assert app_certificates.validate_entries([entry(target=bad)]), bad


def test_two_certificates_cannot_share_or_nest_their_directories():
    errors = app_certificates.validate_entries([entry(target='/certs'), entry(target='/certs')])
    assert any('unique' in message for _, message in errors)

    errors = app_certificates.validate_entries([entry(target='/certs'), entry(target='/certs/inner')])
    assert any('contain one another' in message for _, message in errors)


def test_a_target_inside_a_volume_is_refused_so_no_directory_lands_in_the_operators_data():
    errors = app_certificates.validate_entries([entry(target='/data/certs')], ['/data'])

    assert any('inside the volume' in message for _, message in errors)


def test_a_target_that_would_swallow_a_volume_is_refused_too():
    errors = app_certificates.validate_entries([entry(target='/data')], ['/data/inner'])

    assert any('contains the volume' in message for _, message in errors)


def test_the_same_certificate_may_be_mounted_at_two_directories():
    assert app_certificates.validate_entries(
        [entry(target='/certs'), entry(target='/other')]
    ) == []


# -- the container command line ------------------------------------------------------------

def test_each_entry_is_one_read_only_directory_mount():
    args = podman_create_args(record(certificates=[
        entry(target='/certs'), entry(id=9, target='/tls'),
    ]))

    mounts = [args[index + 1] for index, value in enumerate(args) if value == '--volume']
    assert mounts == [
        '/var/run/freecore-applications/certs/demo/0:/certs:ro',
        '/var/run/freecore-applications/certs/demo/1:/tls:ro',
    ]


def test_a_record_written_before_certificates_existed_is_still_buildable():
    older = record()
    older.pop('certificates')

    args = podman_create_args(older)
    assert '--volume' not in args


def test_the_page_sees_the_reference_and_never_key_material():
    presented = public_record(record(certificates=[entry()]))

    assert presented['certificates'] == [{
        'id': 7, 'name': 'wildcard.example', 'fingerprint': 'AA:BB', 'target': '/certs',
        'restart_on_change': True, 'uid': None, 'gid': None,
    }]
    assert 'privatekey' not in json.dumps(presented)


def test_query_presents_certificates_even_for_a_record_written_before_them():
    older = record()
    older.pop('certificates')

    assert public_record(older)['certificates'] == []


# -- change detection ----------------------------------------------------------------------

def test_the_content_hash_follows_the_rendered_bytes():
    first = {'0': app_certificates.rendered_files(certificate())}
    same = {'0': app_certificates.rendered_files(certificate())}
    renewed = {'0': app_certificates.rendered_files(certificate(chain=(INTERMEDIATE, LEAF)))}

    assert app_certificates.content_hash(first) == app_certificates.content_hash(same)
    assert app_certificates.content_hash(first) != app_certificates.content_hash(renewed)


# -- the edit form -------------------------------------------------------------------------

def installed(**overrides):
    base = record(
        ports=[], environment=[], volumes=[],
        certificates=[entry()],
        portal=None, healthcheck=None, catalog=None, network={'mode': 'managed', 'bridge_address': '10.88.0.5'},
    )
    base.update(overrides)
    return base


def request(**overrides):
    base = {
        'name': 'demo', 'compose_sha256': None, 'ports': [], 'environment': [], 'volumes': [],
        'labels': None, 'certificates': None, 'restart_policy': 'always', 'network': None,
        'health_timeout': 60,
    }
    base.update(overrides)
    return base


def test_an_edit_that_does_not_mention_certificates_keeps_them():
    _, fields, changes = bind_reconfigure(installed(), request())

    assert fields['certificates'] == [entry()]
    assert changes['certificates'] == []


def test_an_empty_list_removes_every_mounted_certificate():
    _, fields, changes = bind_reconfigure(installed(), request(certificates=[]))

    assert fields['certificates'] == []
    assert changes['certificates'] == ['/certs']
    assert anything_changed(changes)


def test_an_edit_can_move_a_certificate_to_another_directory():
    _, fields, changes = bind_reconfigure(
        installed(), request(certificates=[entry(target='/tls')]),
    )

    assert fields['certificates'][0]['target'] == '/tls'
    assert changes['certificates'] == ['/certs', '/tls']


def test_an_edit_that_puts_a_certificate_inside_a_volume_is_refused():
    with pytest.raises(ReconfigureError):
        bind_reconfigure(
            installed(volumes=[{'name': 'data', 'target': '/data', 'read_only': False,
                                'dataset': None, 'owned': True}]),
            request(volumes=[{'name': 'data', 'dataset': None}],
                    certificates=[entry(target='/data/certs')]),
        )


def test_turning_the_restart_off_for_an_entry_is_a_change():
    _, fields, changes = bind_reconfigure(
        installed(), request(certificates=[entry(restart_on_change=False)]),
    )

    assert fields['certificates'][0]['restart_on_change'] is False
    assert changes['certificates'] == ['/certs']


# -- a catalog update keeps the operator's choice -------------------------------------------

def test_a_catalog_update_carries_the_mounted_certificates_forward():
    """The reviewed contract never declares a certificate, so an update must not drop one."""
    from pathlib import Path

    from middlewared.plugins.applications_.catalog import (
        finalize_tag_contract,
        normalize_daemonless_contract,
    )
    from middlewared.plugins.applications_catalog_freebsd import (
        bind_catalog_install,
        bind_catalog_update,
    )
    from middlewared.pytest.unit.plugins.test_applications_catalog import FIXTURES, entry as catalog_entry

    contract = normalize_daemonless_contract(catalog_entry(), (Path(FIXTURES) / 'compose.yaml').read_text())
    detail = finalize_tag_contract(contract)
    detail['catalog'] = {'version': '1.2.3', 'compose_sha256': 'a' * 64}
    detail['provenance'] = {'repository': 'https://github.com/daemonless/demo'}
    update_request = {
        'id': 'daemonless:demo', 'compose_sha256': 'a' * 64, 'name': 'demo',
        'ports': [
            {'host_port': 1, 'container_port': 8080, 'protocol': 'tcp'},
            {'host_port': 2, 'container_port': 8443, 'protocol': 'tcp'},
        ],
        'environment': [{'name': 'MODE', 'value': 'x'}, {'name': 'API_TOKEN', 'value': 'y'}],
        'volumes': [{'name': 'config', 'dataset': None}, {'name': 'media', 'dataset': None}],
        'restart_policy': 'no', 'health_timeout': 5,
    }
    install, provenance = bind_catalog_install(detail, update_request)
    installed_record = {
        'name': 'demo', 'restart_policy': 'always',
        'ports': install['ports'], 'environment': install['environment'],
        'volumes': [
            {**volume, 'source': f'/mnt/tank/{volume["name"]}', 'owned': True}
            for volume in install['volumes']
        ],
        'labels': [],
        'certificates': [entry()],
        'catalog': {**provenance, 'version': '1.0.0'},
    }

    replacement, _, _ = bind_catalog_update(detail, installed_record, update_request)

    assert replacement['certificates'] == [entry()]


# -- the rendered directory ----------------------------------------------------------------

def test_the_entry_directory_is_derived_from_the_record_so_a_renewal_needs_no_recreate():
    assert app_certificates.entry_directory('demo', 0) == \
        '/var/run/freecore-applications/certs/demo/0'
    assert app_certificates.certificates_root('demo') == \
        '/var/run/freecore-applications/certs/demo'
    with pytest.raises(app_certificates.CertificateMountError):
        app_certificates.entry_directory('demo', -1)


def test_the_directory_and_file_modes_keep_the_key_off_other_users():
    # 0750 directory, 0640 files: the application's own uid reads them, nobody else does,
    # and the parent is root-only (set by the service after a render).
    assert stat.S_IMODE(app_certificates.DIRECTORY_MODE) == 0o750
    assert stat.S_IMODE(app_certificates.FILE_MODE) == 0o640


def test_nothing_is_rendered_under_the_pool():
    assert app_certificates.CERTIFICATES_ROOT.startswith('/var/run/')
    assert not app_certificates.CERTIFICATES_ROOT.startswith('/mnt/')
    assert os.path.isabs(app_certificates.CERTIFICATES_ROOT)


# -- the binding survives a renewal and a rename, not another key ---------------------------
#
# An ACME renewal re-orders with the certificate's stored CSR: a new leaf (new serial, new
# fingerprint) over the same key. The entry must stay bound through that -- it is the whole
# point of mounting a renewing certificate -- and through a rename, while a certificate that
# holds the same id but another key (a pool imported on another system) is still refused.

KEY_A = ec.generate_private_key(ec.SECP256R1())
KEY_B = ec.generate_private_key(ec.SECP256R1())


def issued(key, serial, cn='app.example'):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)
    leaf = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(serial)
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    pem = leaf.public_bytes(serialization.Encoding.PEM).decode()
    return {
        'id': 7, 'name': 'wildcard.example', 'revoked': False,
        'fingerprint': leaf.fingerprint(hashes.SHA1()).hex(':').upper(),
        'certificate': pem, 'chain_list': [pem],
        'privatekey': key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode(),
    }


ORIGINAL = issued(KEY_A, 1)
RENEWED = issued(KEY_A, 2)          # same key, new leaf: what renew_certs writes
FOREIGN = issued(KEY_B, 1)          # same id on another system, another key


def bound(certificate=ORIGINAL, **overrides):
    return entry(
        name=certificate['name'], fingerprint=certificate['fingerprint'],
        public_key_sha256=app_certificates.public_key_sha256(certificate), **overrides,
    )


def test_a_renewal_keeps_the_key_and_another_certificate_does_not():
    assert RENEWED['fingerprint'] != ORIGINAL['fingerprint']
    assert app_certificates.public_key_sha256(RENEWED) == app_certificates.public_key_sha256(ORIGINAL)
    assert app_certificates.public_key_sha256(FOREIGN) != app_certificates.public_key_sha256(ORIGINAL)


def test_a_renewed_certificate_is_still_the_one_the_entry_is_bound_to():
    assert ApplicationsService._certificate_reference(bound(), RENEWED) is RENEWED


def test_a_renamed_certificate_is_still_the_one_the_entry_is_bound_to():
    renamed = dict(ORIGINAL, name='renamed.example')
    assert ApplicationsService._certificate_reference(bound(), renamed) is renamed


def test_another_key_under_the_same_id_is_refused():
    with pytest.raises(CallError, match='different key'):
        ApplicationsService._certificate_reference(bound(), FOREIGN)


def test_a_certificate_gone_from_the_store_is_refused():
    with pytest.raises(CallError, match='no longer in the certificate store'):
        ApplicationsService._certificate_reference(bound(), None)


def test_an_entry_bound_before_the_key_was_recorded_is_checked_by_fingerprint():
    older = entry(name=ORIGINAL['name'], fingerprint=ORIGINAL['fingerprint'])
    assert ApplicationsService._certificate_reference(older, ORIGINAL) is ORIGINAL
    with pytest.raises(CallError, match='choose it again'):
        ApplicationsService._certificate_reference(older, RENEWED)


def test_the_record_keeps_the_key_and_a_malformed_one_is_refused():
    assert bound()['public_key_sha256'] == app_certificates.bound_entry(bound())['public_key_sha256']
    assert 'public_key_sha256' not in app_certificates.bound_entry(entry())
    errors = app_certificates.validate_entries([entry(public_key_sha256='not-a-digest')])
    assert errors and errors[0][0] == 'certificates.0.public_key_sha256'
    # The page sees the reference, not the binding.
    assert 'public_key_sha256' not in public_record(record(certificates=[bound()]))['certificates'][0]


def test_a_renewal_or_a_rename_alone_changes_nothing_mounted():
    refreshed = bound(RENEWED)
    refreshed['name'] = 'renamed.example'
    _, fields, changes = bind_reconfigure(
        installed(certificates=[bound()]), request(certificates=[refreshed]),
    )
    assert changes['certificates'] == [] and not anything_changed(changes)
    assert fields['certificates'][0]['fingerprint'] == RENEWED['fingerprint']


def test_a_new_key_under_the_same_id_is_a_change():
    _, _, changes = bind_reconfigure(
        installed(certificates=[bound()]), request(certificates=[bound(FOREIGN)]),
    )
    assert changes['certificates'] == ['/certs']


# -- an edit binds its rows to the store before anything is touched ---------------------------

def store_service(store):
    """An ApplicationsService whose certificate store is ``store`` ({id: certificate})."""
    calls = []
    alerts = []

    async def call(method, *args):
        calls.append(method)
        if method in ('alert.oneshot_create', 'alert.oneshot_delete'):
            alerts.append((method.rsplit('_', 1)[1], args[0], args[1]))
            return None
        if method == 'certificate.query':
            found = store.get(args[0][0][2])
            return [found] if found else []
        if method == 'certificate.cert_services_validation':
            verrors = ValidationErrors()
            certificate = store.get(args[0])
            if certificate and certificate.get('revoked'):
                verrors.add(args[1], 'This certificate is revoked')
            return verrors
        raise AssertionError(method)

    middleware = Mock()
    middleware.call = AsyncMock(side_effect=call)
    service = ApplicationsService(middleware)
    service.alerts = alerts
    return service, calls


def form_row(certificate, **overrides):
    """A row as the edit form sends it: id, name and fingerprint, never the key."""
    row = entry(name=certificate['name'], fingerprint=certificate['fingerprint'])
    row.update(overrides)
    return row


@pytest.mark.asyncio
async def test_a_row_carried_over_after_a_renewal_keeps_its_binding():
    svc, calls = store_service({7: RENEWED})
    rows = await svc._bind_requested_certificates(
        installed(certificates=[bound()]), [form_row(ORIGINAL)], 'applications_reconfigure.certificates',
    )
    assert rows[0]['fingerprint'] == RENEWED['fingerprint']
    assert rows[0]['public_key_sha256'] == app_certificates.public_key_sha256(ORIGINAL)
    # Not a new binding: the host-service rules are not asked again.
    assert 'certificate.cert_services_validation' not in calls


@pytest.mark.asyncio
async def test_a_row_chosen_now_binds_to_the_store_and_passes_the_host_rules():
    svc, calls = store_service({7: ORIGINAL})
    rows = await svc._bind_requested_certificates(
        installed(certificates=[]), [form_row(ORIGINAL)], 'applications_reconfigure.certificates',
    )
    assert rows[0]['public_key_sha256'] == app_certificates.public_key_sha256(ORIGINAL)
    assert 'certificate.cert_services_validation' in calls


@pytest.mark.asyncio
async def test_a_revoked_certificate_cannot_be_newly_mounted_by_an_edit():
    svc, _ = store_service({7: dict(ORIGINAL, revoked=True)})
    with pytest.raises(ValidationErrors, match='revoked'):
        await svc._bind_requested_certificates(
            installed(certificates=[]), [form_row(ORIGINAL)], 'applications_reconfigure.certificates',
        )


@pytest.mark.asyncio
async def test_a_row_that_matches_neither_the_record_nor_the_store_is_refused():
    svc, _ = store_service({7: RENEWED})
    with pytest.raises(ValidationErrors, match='changed since the form was opened'):
        await svc._bind_requested_certificates(
            installed(certificates=[]), [form_row(ORIGINAL)], 'applications_reconfigure.certificates',
        )


@pytest.mark.asyncio
async def test_a_carried_over_row_whose_id_now_holds_another_key_is_refused():
    svc, _ = store_service({7: FOREIGN})
    with pytest.raises(ValidationErrors, match='different key'):
        await svc._bind_requested_certificates(
            installed(certificates=[bound()]), [form_row(ORIGINAL)], 'applications_reconfigure.certificates',
        )


@pytest.mark.asyncio
async def test_a_row_whose_certificate_is_gone_is_refused():
    svc, _ = store_service({})
    with pytest.raises(ValidationErrors, match='no longer in the certificate store'):
        await svc._bind_requested_certificates(
            installed(certificates=[bound()]), [form_row(ORIGINAL)], 'applications_reconfigure.certificates',
        )


@pytest.mark.asyncio
async def test_an_install_records_the_key_of_each_certificate():
    svc, _ = store_service({7: ORIGINAL})
    rows = await svc._bind_install_certificates([form_row(ORIGINAL)])
    assert rows == [bound()]


# -- a failed replacement puts the prior container's files back -----------------------------

@pytest.mark.asyncio
async def test_a_failed_replacement_renders_the_prior_record_before_the_rollback():
    middleware = Mock()
    middleware.call = AsyncMock()
    svc = ApplicationsService(middleware)
    current = record(certificates=[bound(target='/certs'), bound(target='/tls')])
    replacement = record(certificates=[])           # the edit removed both
    order = []

    async def render(rec):
        order.append(('render', len(rec['certificates'])))
    svc.render_certificates = AsyncMock(side_effect=render)
    svc._inspect_owned_container = AsyncMock(return_value=None)
    svc._prepare_lan_network = AsyncMock(return_value=None)
    svc._podman = AsyncMock(side_effect=CallError('create failed'))

    async def rollback(*args):
        order.append(('rollback',))
        return []
    svc._rollback_catalog_replacement = AsyncMock(side_effect=rollback)

    with (
        patch('middlewared.plugins.applications_freebsd.podman_create_args', return_value=['podman', 'create']),
        patch('middlewared.plugins.applications_freebsd.temporary_environment_file',
              side_effect=lambda rec: contextlib.nullcontext()),
    ):
        with pytest.raises(CallError, match='create failed'):
            await svc._replace_container(Mock(), {'pool': 'tank'}, current, replacement, 0, 'reconfigure')

    assert order == [('render', 0), ('render', 2), ('rollback',)]


@pytest.mark.asyncio
async def test_a_prior_record_that_cannot_be_rendered_again_makes_the_rollback_incomplete():
    middleware = Mock()
    middleware.call = AsyncMock()
    svc = ApplicationsService(middleware)
    current = record(certificates=[bound()])
    svc.render_certificates = AsyncMock(side_effect=[None, CallError('store unavailable')])
    svc._inspect_owned_container = AsyncMock(return_value=None)
    svc._prepare_lan_network = AsyncMock(return_value=None)
    svc._podman = AsyncMock(side_effect=CallError('create failed'))
    svc._rollback_catalog_replacement = AsyncMock(return_value=[])

    with (
        patch('middlewared.plugins.applications_freebsd.podman_create_args', return_value=['podman', 'create']),
        patch('middlewared.plugins.applications_freebsd.temporary_environment_file',
              side_effect=lambda rec: contextlib.nullcontext()),
    ):
        with pytest.raises(
            CallError, match=r'rollback was incomplete: restore mounted certificates: .*store unavailable',
        ):
            await svc._replace_container(Mock(), {'pool': 'tank'}, current, record(), 0, 'reconfigure')


# -- every form -> method pair passes the public schema ---------------------------------------
#
# The job tests call `.wraps()` and never meet `accepts`; an undeclared field is refused by
# the schema with "Field was not expected" and the whole request fails (the the internal development record trap).

PAGE_CERTIFICATES = [{
    'id': 7, 'name': 'wildcard.example', 'fingerprint': 'AA:BB', 'target': '/certs',
    'restart_on_change': True, 'uid': None, 'gid': 1000,
}]


def through(schema, payload):
    value = schema.clean(copy.deepcopy(payload))
    schema.validate(value)
    return value


def test_the_catalog_install_form_payload_is_accepted():
    # applications.store.ts install(): exactly what the page sends to applications.catalog.install.
    payload = {
        'id': 'daemonless:demo', 'compose_sha256': 'a' * 64, 'name': 'demo',
        'ports': [{'host_port': 18080, 'container_port': 8080, 'protocol': 'tcp'}],
        'environment': [{'name': 'MODE', 'value': 'x'}],
        'volumes': [{'name': 'config', 'dataset': None}],
        'labels': [],
        'certificates': PAGE_CERTIFICATES,
        'restart_policy': 'always', 'health_timeout': 60,
        'network': {'mode': 'managed'},
    }
    value = through(CATALOG_INSTALL_SCHEMA, payload)
    assert value['certificates'] == PAGE_CERTIFICATES
    assert set(payload) <= set(CATALOG_INSTALL_SCHEMA.attrs)


def test_the_edit_form_payload_is_accepted():
    schema = ApplicationsService.reconfigure.accepts[0]
    payload = {
        'name': 'demo', 'compose_sha256': None, 'ports': [], 'environment': [], 'volumes': [],
        'labels': [], 'certificates': PAGE_CERTIFICATES, 'restart_policy': 'always',
        'health_timeout': 60, 'network': {'mode': 'managed'},
    }
    assert through(schema, payload)['certificates'] == PAGE_CERTIFICATES
    assert set(payload) <= set(schema.attrs)


def test_the_install_method_declares_certificates():
    assert 'certificates' in ApplicationsService.install.accepts[0].attrs


@pytest.mark.parametrize('schema', [
    CATALOG_INSTALL_SCHEMA,
    ApplicationsService.reconfigure.accepts[0],
])
def test_a_caller_cannot_state_the_key_binding(schema):
    row = dict(PAGE_CERTIFICATES[0], public_key_sha256='0' * 64)
    payload = {'certificates': [row]}
    with pytest.raises(Exception, match='Field was not expected'):
        value = schema.clean(copy.deepcopy(payload))
        schema.validate(value)


# -- the files on disk ------------------------------------------------------------------------
#
# The same code that runs on a box, writing into a temporary directory: what the modes are,
# what a second pass and a renewal do to a directory a running container has mounted, and
# what is left when the list gets shorter.

def rendering_service(tmp_path, monkeypatch, store):
    monkeypatch.setattr(app_certificates, 'CERTIFICATES_ROOT', str(tmp_path / 'certs'))
    svc, _ = store_service(store)

    async def run_in_thread(function, *args):
        return function(*args)
    svc.middleware.run_in_thread = AsyncMock(side_effect=run_in_thread)
    return svc, tmp_path / 'certs' / 'demo'


def mounted(**overrides):
    # The files go to the PUID/PGID the image declares: here, the user running the tests.
    base = record(
        environment=[{'name': 'PUID', 'value': str(os.getuid())}, {'name': 'PGID', 'value': str(os.getgid())}],
        certificates=[bound()],
    )
    base.update(overrides)
    return base


@pytest.mark.asyncio
async def test_a_render_writes_the_four_files_where_only_root_and_the_application_reach_them(
    tmp_path, monkeypatch,
):
    svc, root = rendering_service(tmp_path, monkeypatch, {7: ORIGINAL})

    result = await svc.render_certificates(mounted())

    directory = root / '0'
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(directory.stat().st_mode) == 0o750
    assert sorted(path.name for path in directory.iterdir()) == [
        'cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem',
    ]
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o640 for path in directory.iterdir())
    assert all(path.stat().st_uid == os.getuid() for path in directory.iterdir())
    assert (directory / 'privkey.pem').read_text() == ORIGINAL['privatekey'].strip() + '\n'
    assert (directory / 'cert.pem').read_text().strip() == ORIGINAL['certificate'].strip()
    assert (directory / 'chain.pem').read_text() == ''
    assert result['changed'] == [0] and result['restart'] is True


@pytest.mark.asyncio
async def test_a_second_render_of_the_same_bytes_changes_nothing(tmp_path, monkeypatch):
    svc, _ = rendering_service(tmp_path, monkeypatch, {7: ORIGINAL})

    first = await svc.render_certificates(mounted())
    second = await svc.render_certificates(mounted())

    assert second == {'hash': first['hash'], 'changed': [], 'restart': False}


@pytest.mark.asyncio
async def test_a_renewal_rewrites_the_files_inside_the_directory_a_container_has_mounted(
    tmp_path, monkeypatch,
):
    store = {7: ORIGINAL}
    svc, root = rendering_service(tmp_path, monkeypatch, store)
    await svc.render_certificates(mounted())
    mounted_directory = (root / '0').stat().st_ino

    store[7] = RENEWED
    result = await svc.render_certificates(mounted())

    assert result['changed'] == [0] and result['restart'] is True
    # The directory is a bind-mount source: replacing it would leave the container the old one.
    assert (root / '0').stat().st_ino == mounted_directory
    assert (root / '0' / 'cert.pem').read_text().strip() == RENEWED['certificate'].strip()
    assert sorted(path.name for path in (root / '0').iterdir()) == [
        'cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem',
    ]


@pytest.mark.asyncio
async def test_a_changed_entry_that_did_not_ask_for_a_restart_gets_none(tmp_path, monkeypatch):
    store = {7: ORIGINAL}
    svc, _ = rendering_service(tmp_path, monkeypatch, store)
    quiet = mounted(certificates=[bound(restart_on_change=False)])
    await svc.render_certificates(quiet)

    store[7] = RENEWED
    result = await svc.render_certificates(quiet)

    assert result['changed'] == [0] and result['restart'] is False


@pytest.mark.asyncio
async def test_an_entry_dropped_from_the_list_leaves_no_key_behind(tmp_path, monkeypatch):
    svc, root = rendering_service(tmp_path, monkeypatch, {7: ORIGINAL})
    await svc.render_certificates(mounted(certificates=[bound(target='/certs'), bound(target='/tls')]))
    (root / '0' / 'left-by-a-crash').write_text('x')
    assert (root / '1' / 'privkey.pem').is_file()

    await svc.render_certificates(mounted(certificates=[bound(target='/certs')]))
    assert not (root / '1').exists()
    assert not (root / '0' / 'left-by-a-crash').exists()

    await svc.render_certificates(mounted(certificates=[]))
    assert not root.exists()


@pytest.mark.asyncio
async def test_another_key_under_the_same_id_is_not_written_over_the_mounted_files(tmp_path, monkeypatch):
    store = {7: ORIGINAL}
    svc, root = rendering_service(tmp_path, monkeypatch, store)
    await svc.render_certificates(mounted())

    store[7] = FOREIGN
    with pytest.raises(CallError, match='different key'):
        await svc.render_certificates(mounted())

    assert (root / '0' / 'privkey.pem').read_text() == ORIGINAL['privatekey'].strip() + '\n'


# -- the reconcile pass -----------------------------------------------------------------------

def changed(restart=True):
    return {'hash': 'h', 'changed': [0], 'restart': restart}


UNCHANGED = {'hash': 'h', 'changed': [], 'restart': False}


def reconciling_service(records, renders, running=True):
    svc, _ = store_service({})
    svc.config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': True})
    svc._read_records = Mock(return_value=(records, []))

    async def render(rec):
        outcome = renders[rec['name']]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    svc.render_certificates = AsyncMock(side_effect=render)
    svc._inspect_owned_container = AsyncMock(return_value=({'State': {'Running': running}}, 'c' * 64))
    svc._prepare_lan_network = AsyncMock()
    svc._podman = AsyncMock()
    return svc


def app(name, **overrides):
    return record(name=name, certificates=[bound()], **overrides)


async def reconcile(svc, certificate_ids=None):
    return await ApplicationsService.reconcile_certificates(svc, Mock(), certificate_ids)


@pytest.mark.asyncio
async def test_a_renewal_restarts_a_running_application_that_asked_for_it_once():
    svc = reconciling_service([app('proxy')], {'proxy': changed()})

    assert await reconcile(svc, [7]) == {'rendered': ['proxy'], 'restarted': ['proxy']}

    svc._podman.assert_awaited_once()
    assert svc._podman.await_args.args[1:] == ('restart', 'c' * 64)
    assert ('delete', 'ApplicationsCertificateRestartFailed', 'proxy') in svc.alerts


@pytest.mark.asyncio
async def test_a_stopped_application_gets_the_files_and_stays_stopped():
    svc = reconciling_service([app('proxy')], {'proxy': changed()}, running=False)

    assert await reconcile(svc, [7]) == {'rendered': ['proxy'], 'restarted': []}
    svc._podman.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_application_that_reloads_by_itself_is_not_restarted():
    svc = reconciling_service([app('proxy')], {'proxy': changed(restart=False)})

    assert await reconcile(svc, [7]) == {'rendered': ['proxy'], 'restarted': []}
    svc._podman.assert_not_awaited()
    svc._inspect_owned_container.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_pass_over_unchanged_files_restarts_nothing():
    svc = reconciling_service([app('proxy')], {'proxy': UNCHANGED})

    assert await reconcile(svc) == {'rendered': [], 'restarted': []}
    svc._podman.assert_not_awaited()


@pytest.mark.asyncio
async def test_only_the_applications_that_mount_the_renewed_certificate_are_touched():
    other = record(name='other', certificates=[dict(bound(), id=9)])
    plain = record(name='plain')
    svc = reconciling_service([app('proxy'), other, plain], {'proxy': changed(), 'other': changed()})

    assert await reconcile(svc, [7]) == {'rendered': ['proxy'], 'restarted': ['proxy']}
    assert [call.args[0]['name'] for call in svc.render_certificates.await_args_list] == ['proxy']


@pytest.mark.asyncio
async def test_one_application_that_cannot_be_rendered_does_not_stop_the_pass():
    svc = reconciling_service(
        [app('broken'), app('proxy')],
        {'broken': CallError('no longer in the certificate store'), 'proxy': changed()},
    )

    assert await reconcile(svc, [7]) == {'rendered': ['proxy'], 'restarted': ['proxy']}

    created = [item for item in svc.alerts if item[0] == 'create']
    assert [(klass, args['application']) for _, klass, args in created] == [
        ('ApplicationsCertificateRenderFailed', 'broken'),
    ]
    assert 'no longer in the certificate store' in created[0][2]['error']
    assert ('delete', 'ApplicationsCertificateRenderFailed', 'proxy') in svc.alerts


@pytest.mark.asyncio
async def test_a_restart_that_fails_raises_one_alert_and_the_pass_goes_on():
    svc = reconciling_service([app('first'), app('second')], {'first': changed(), 'second': changed()})
    svc._podman = AsyncMock(side_effect=[CallError('restart refused'), None])

    assert await reconcile(svc, [7]) == {'rendered': ['first', 'second'], 'restarted': ['second']}

    created = [(klass, args['application']) for kind, klass, args in svc.alerts if kind == 'create']
    assert created == [('ApplicationsCertificateRestartFailed', 'first')]


@pytest.mark.asyncio
async def test_nothing_is_rendered_while_the_runtime_is_down():
    svc = reconciling_service([app('proxy')], {'proxy': changed()})
    svc.config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': False})

    assert (await reconcile(svc))['skipped'] == 'runtime_not_ready'
    svc.render_certificates.assert_not_awaited()


@pytest.mark.asyncio
async def test_the_pass_holds_the_lifecycle_locks_while_it_renders():
    """An edit renders its replacement's directories before it commits the record; a pass
    that could run in between would write the previous list over them."""
    assert ApplicationsService.reconcile_certificates._job['lock'] == 'applications_lifecycle'
    assert ApplicationsService.reconfigure._job['lock'] == 'applications_lifecycle'
    held = []
    svc = reconciling_service([app('proxy')], {'proxy': UNCHANGED})

    async def render(rec):
        held.append(service_module.LOCKS['applications_lifecycle_internal'].locked())
        return UNCHANGED
    svc.render_certificates = AsyncMock(side_effect=render)

    await reconcile(svc)

    assert held == [True]
    assert not service_module.LOCKS['applications_lifecycle_internal'].locked()


# -- the delete guard -------------------------------------------------------------------------

def guarded_service(monkeypatch, records_path, records=()):
    svc, _ = store_service({})
    svc.config = AsyncMock(return_value={'pool': 'tank'})
    monkeypatch.setattr(
        'middlewared.plugins.applications_freebsd.application_paths',
        lambda pool: {'records': str(records_path)},
    )
    svc._read_records = Mock(return_value=(list(records), []))
    return svc


@pytest.mark.asyncio
async def test_the_delete_guard_names_the_applications_that_mount_the_certificate(tmp_path, monkeypatch):
    svc = guarded_service(monkeypatch, tmp_path, [app('web'), app('proxy'), record(name='plain')])

    assert await svc.certificates_in_use(7) == ['proxy', 'web']
    assert await svc.certificates_in_use(8) == []


@pytest.mark.asyncio
async def test_no_applications_pool_means_nothing_can_mount_it(tmp_path, monkeypatch):
    svc = guarded_service(monkeypatch, tmp_path, [app('web')])
    svc.config = AsyncMock(return_value={'pool': None})

    assert await svc.certificates_in_use(7) == []


@pytest.mark.asyncio
async def test_a_pool_that_is_not_there_is_not_read_as_unused(tmp_path, monkeypatch):
    svc = guarded_service(monkeypatch, tmp_path / 'exported', [app('web')])

    with pytest.raises(CallError, match='is not available') as refused:
        await svc.certificates_in_use(7)
    assert refused.value.errno == errno.EBUSY


@pytest.mark.asyncio
async def test_unreadable_records_are_not_read_as_unused(tmp_path, monkeypatch):
    svc = guarded_service(monkeypatch, tmp_path)
    svc._read_records = Mock(side_effect=OSError('input/output error'))

    with pytest.raises(CallError, match='records are unreadable') as refused:
        await svc.certificates_in_use(7)
    assert refused.value.errno == errno.EBUSY


# -- the alerts follow the state --------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_boot_render_that_fails_is_an_alert_and_the_other_applications_still_render():
    svc, _ = store_service({})
    svc.config = AsyncMock(return_value={'pool': 'tank', 'runtime_ready': True, 'restart_on_boot': True})
    svc._read_records = Mock(return_value=([app('broken'), app('proxy'), record(name='plain')], []))

    async def render(rec):
        if rec['name'] == 'broken':
            raise CallError('no longer in the certificate store')
        return changed()
    svc.render_certificates = AsyncMock(side_effect=render)
    svc._inspect_managed_containers = AsyncMock(return_value={})

    await svc._start_on_boot_impl()

    assert [call.args[0]['name'] for call in svc.render_certificates.await_args_list] == ['broken', 'proxy']
    created = [(klass, args['application']) for kind, klass, args in svc.alerts if kind == 'create']
    assert created == [('ApplicationsCertificateRenderFailed', 'broken')]
    assert ('delete', 'ApplicationsCertificateRenderFailed', 'proxy') in svc.alerts


def lifecycle_service(rec):
    svc, _ = store_service({})
    svc._require_config = AsyncMock(return_value={'pool': 'tank'})
    svc._get_record = Mock(return_value=rec)
    svc._require_owned_container = AsyncMock(return_value=({}, 'c' * 64))
    svc._prepare_lan_network = AsyncMock()
    svc.render_certificates = AsyncMock(return_value=UNCHANGED)
    svc._podman = AsyncMock()
    return svc


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['start', 'restart'])
async def test_a_start_that_goes_through_clears_the_certificate_alerts(method):
    svc = lifecycle_service(app('proxy'))

    assert await getattr(ApplicationsService, method).wraps(svc, Mock(), 'proxy') is True

    assert svc.alerts == [
        ('delete', 'ApplicationsCertificateRenderFailed', 'proxy'),
        ('delete', 'ApplicationsCertificateRestartFailed', 'proxy'),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize('method', ['start', 'restart'])
async def test_a_start_that_cannot_render_keeps_the_alerts_and_starts_nothing(method):
    svc = lifecycle_service(app('proxy'))
    svc.render_certificates = AsyncMock(side_effect=CallError('different key'))

    with pytest.raises(CallError, match='different key'):
        await getattr(ApplicationsService, method).wraps(svc, Mock(), 'proxy')

    svc._podman.assert_not_awaited()
    assert svc.alerts == []


@pytest.mark.asyncio
async def test_an_application_without_certificates_costs_no_alert_call():
    svc = lifecycle_service(record(name='plain'))

    await ApplicationsService.start.wraps(svc, Mock(), 'plain')

    assert svc.alerts == []
