"""FreeCORE iocage plugin-store retirement acceptance."""

import os
import sys

import pytest

apifolder = os.getcwd()
sys.path.append(apifolder)

from auto_config import dev_test, ha
from functions import GET, POST, wait_on_job


pytestmark = pytest.mark.skipif(dev_test, reason='Skip for test development')

RETIRED_MESSAGE = 'The iocage plugin store has been retired.'


def assert_retired_job(response):
    assert response.status_code == 200, response.text
    assert isinstance(response.json(), int), response.text

    job_status = wait_on_job(response.json(), 30)
    assert job_status['state'] == 'FAILED', str(job_status['results'])
    assert RETIRED_MESSAGE in job_status['results']['error'], str(job_status['results'])


@pytest.mark.skipif(ha, reason='Jails are unavailable on HA systems')
def test_installed_plugin_compatibility_query_remains_local():
    response = GET('/plugin/')

    assert response.status_code == 200, response.text
    assert isinstance(response.json(), list), response.text


@pytest.mark.skipif(ha, reason='Jails are unavailable on HA systems')
def test_no_official_iocage_plugin_repositories_are_advertised():
    response = GET('/plugin/official_repositories/')

    assert response.status_code == 200, response.text
    assert response.json() == {}, response.text


@pytest.mark.skipif(ha, reason='Jails are unavailable on HA systems')
def test_available_plugin_catalog_is_retired():
    assert_retired_job(POST('/plugin/available/', {}))


@pytest.mark.skipif(ha, reason='Jails are unavailable on HA systems')
def test_new_plugin_creation_is_retired():
    assert_retired_job(POST('/plugin/', {
        'plugin_name': 'transmission',
        'jail_name': 'must-not-be-created',
        'props': [],
        'plugin_repository': 'https://example.invalid/plugin-index.git',
    }))


@pytest.mark.skipif(ha, reason='Jails are unavailable on HA systems')
def test_hidden_jail_fetch_plugin_creation_is_retired():
    assert_retired_job(POST('/jail/fetch/', {
        'name': 'transmission',
        'jail_name': 'must-not-be-created',
        'props': [],
    }))
