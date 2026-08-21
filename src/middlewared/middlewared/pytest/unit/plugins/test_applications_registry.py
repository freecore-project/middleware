"""the internal development record: the registry probe says whether a missing tag is definitive."""
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from middlewared.plugins.applications_ import registry


def completed(returncode, stdout='', stderr=''):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# stderr lines as skopeo 1.x printed them on a 15.1-MASTER appliance, 2026-09-13
MISSING_TAG = (
    'time="2026-09-13T13:13:14-07:00" level=fatal msg="Error parsing image name '
    '\\"docker://ghcr.io/daemonless/forgejo:latest\\": reading manifest latest in '
    'ghcr.io/daemonless/forgejo: manifest unknown"'
)
NO_ROUTE = (
    'time="2026-09-13T13:13:17-07:00" level=fatal msg="Error parsing image name '
    '\\"docker://ghcr.io/daemonless/postgres:latest\\": pinging container registry ghcr.io: '
    'Get \\"https://ghcr.io/v2/\\": tls: failed to verify certificate"'
)
FORBIDDEN = (
    'time="2026-09-13T13:13:14-07:00" level=fatal msg="Error parsing image name '
    '\\"docker://ghcr.io/daemonless/no-such-repo-xyz:latest\\": Requesting bearer token: '
    'received unexpected HTTP status: 403 Forbidden"'
)
TIMEOUT = 'level=fatal msg="... pinging container registry 192.0.2.1: context deadline exceeded"'


@pytest.mark.asyncio
@pytest.mark.parametrize('returncode, stderr, verdict', [
    (2, MISSING_TAG, registry.VERDICT_MISSING),
    (1, NO_ROUTE, registry.VERDICT_UNKNOWN),
    (1, FORBIDDEN, registry.VERDICT_UNKNOWN),
    (1, TIMEOUT, registry.VERDICT_UNKNOWN),
    (1, '', registry.VERDICT_UNKNOWN),
])
async def test_only_manifest_unknown_is_a_definitive_absence(returncode, stderr, verdict):
    with patch.object(registry, 'run', AsyncMock(return_value=completed(returncode, stderr=stderr))):
        inspection, seen = await registry.probe_remote_image('ghcr.io/daemonless/forgejo:latest')
    assert inspection is None
    assert seen == verdict


@pytest.mark.asyncio
async def test_a_found_image_is_described_and_inspect_remote_image_keeps_its_shape():
    summary = (
        '{"Digest": "sha256:%s", "Os": "freebsd", "Architecture": "amd64", "Labels": {"a": "b"}}' % ('9' * 64)
    )
    config = (
        '{"os": "freebsd", "architecture": "amd64", "config": {"Env": ["PUID=1000"], "Entrypoint": ["/init"]}}'
    )
    outputs = iter([completed(0, stdout=summary), completed(0, stdout=config)])
    with patch.object(registry, 'run', AsyncMock(side_effect=lambda *a, **k: next(outputs))):
        inspection, verdict = await registry.probe_remote_image('ghcr.io/daemonless/postgres:latest')
    assert verdict == registry.VERDICT_FOUND
    assert inspection['reference'] == 'ghcr.io/daemonless/postgres:latest'
    assert inspection['digest'] == 'sha256:' + '9' * 64
    assert inspection['environment'] == {'PUID': '1000'}
    assert inspection['entrypoint'] == ['/init']

    outputs = iter([completed(0, stdout=summary), completed(0, stdout=config)])
    with patch.object(registry, 'run', AsyncMock(side_effect=lambda *a, **k: next(outputs))):
        again = await registry.inspect_remote_image('ghcr.io/daemonless/postgres:latest')
    assert again['digest'] == inspection['digest']


@pytest.mark.asyncio
async def test_skopeo_absent_is_unknown_not_missing():
    with patch.object(registry, 'run', AsyncMock(side_effect=FileNotFoundError())):
        probe = await registry.probe_remote_image('ghcr.io/daemonless/forgejo:latest')
    assert probe == (None, registry.VERDICT_UNKNOWN)
