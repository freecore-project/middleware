
"""FreeCORE plugin-origin acceptance; intentionally not part of 13.3 parity."""

import os
import pytest
import sys
from pytest_dependency import depends
apifolder = os.getcwd()
sys.path.append(apifolder)
from auto_config import pool_name, ha, dev_test
from functions import GET, POST, DELETE, wait_on_job

reason = 'Skip for test development'
# comment pytestmark for development testing with --dev-test
pytestmark = pytest.mark.skipif(dev_test, reason=reason)


# Exclude from HA testing
if not ha:
    job_results = None
    test_repos_url = (
        'https://plugins.freecore.org/plugins/git/'
        'iocage-freecore-plugins.git'
    )

    plugins_branch = 'main'
    repos_url = test_repos_url

    plugin_objects = [
        "id",
        "state",
        "type",
        "release",
        "plugin_repository"
    ]

    default_plugins = [
        'syncthing',
        'transmission',
    ]
    plugin_list = default_plugins

    @pytest.mark.dependency(name="ACTIVATE_JAIL_POOL")
    def test_03_activate_jail_pool(request):
        depends(request, ["pool_04"], scope="session")
        results = POST('/jail/activate/', pool_name)
        assert results.status_code == 200, results.text
        assert results.json() is True, results.text

    def test_04_verify_jail_pool(request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        results = GET('/jail/get_activated_pool/')
        assert results.status_code == 200, results.text
        assert results.json() == pool_name, results.text

    def test_05_get_list_of_installed_plugin(request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        results = GET('/plugin/')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), list), results.text

    def test_06_verify_plugin_repos_is_in_official_repositories(request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        results = GET('/plugin/official_repositories/')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), dict), results.text
        assert 'FREECORE' in results.json(), results.text
        assert results.json()['FREECORE']['name'] == 'FreeCORE', results.text
        assert results.json()['FREECORE']['git_repository'] == test_repos_url, results.text

    def test_07_get_list_of_default_plugins_available_job_id(request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        global job_results
        results = POST('/plugin/available/')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), int), results.text
        job_status = wait_on_job(results.json(), 180)
        assert job_status['state'] == 'SUCCESS', str(job_status['results'])
        job_results = job_status['results']

    @pytest.mark.parametrize('plugin', default_plugins)
    def test_08_verify_available_plugin_(plugin, request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        assert isinstance(job_results['result'], list), str(job_results)
        assert plugin in [p['plugin'] for p in job_results['result']], str(job_results['result'])

    @pytest.mark.parametrize('prop', ['version', 'revision', 'epoch'])
    def test_09_verify_available_plugins_syncthing_is_not_na_with(prop, request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        for plugin_info in job_results['result']:
            if 'syncthing' in plugin_info['plugin']:
                break
        assert plugin_info[prop] != 'N/A', str(job_results)

    @pytest.mark.timeout(1200)
    @pytest.mark.dependency(name="ADD_SYNCTHING_PLUGIN")
    def test_10_add_syncthing_plugin(request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        payload = {
            "plugin_name": "syncthing",
            "jail_name": "syncthing",
            'props': [
                'nat=1'
            ],
            "plugin_repository": test_repos_url
        }
        results = POST('/plugin/', payload)
        assert results.status_code == 200, results.text
        job_status = wait_on_job(results.json(), 1200)
        assert job_status['state'] == 'SUCCESS', str(job_status['results'])

    def test_11_search_plugin_syncthing_id(request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        results = GET('/plugin/?id=syncthing')
        assert results.status_code == 200, results.text
        assert len(results.json()) > 0, results.text

    def test_12_get_syncthing_plugin_info(request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        global syncthing_plugin
        results = GET('/plugin/id/syncthing/')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), dict), results.text
        syncthing_plugin = results.json()

    @pytest.mark.parametrize('prop', ['version', 'revision', 'epoch'])
    def test_13_verify_syncthing_plugin_value_is_not_na_for_(prop, request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        assert syncthing_plugin[prop] != 'N/A', str(syncthing_plugin)

    @pytest.mark.parametrize('prop', ['version', 'revision', 'epoch'])
    def test_14_verify_syncthing_plugins_installed_and_available_value_(prop, request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        for plugin_info in job_results['result']:
            if 'syncthing' in plugin_info['plugin']:
                break
        assert plugin_info[prop] == syncthing_plugin[prop], str(plugin_info)

    def test_15_get_syncthing_jail_info(request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        global syncthing_jail, results
        results = GET("/jail/id/syncthing")
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), dict), results.text
        syncthing_jail = results.json()

    @pytest.mark.parametrize('prop', plugin_objects)
    def test_16_verify_syncthing_plugin_value_with_jail_value_of_(prop, request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        assert syncthing_jail[prop] == syncthing_plugin[prop], results.text

    def test_17_get_list_of_available_plugins_without_cache(request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        global job_results
        payload = {
            "plugin_repository": repos_url,
            "cache": False
        }
        results = POST('/plugin/available/', payload)
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), int), results.text
        job_status = wait_on_job(results.json(), 180)
        assert job_status['state'] == 'SUCCESS', str(job_status['results'])
        job_results = job_status['results']

    @pytest.mark.parametrize('plugin', plugin_list)
    def test_18_verify_available_plugin_without_cache_(plugin, request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        assert isinstance(job_results['result'], list), str(job_results)
        assert plugin in [p['plugin'] for p in job_results['result']], str(job_results['result'])

    def test_19_stop_syncthing_jail(request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        payload = {
            "jail": "syncthing",
            "force": True
        }
        results = POST('/jail/stop/', payload)
        assert results.status_code == 200, results.text
        job_status = wait_on_job(results.json(), 60)
        assert job_status['state'] == 'SUCCESS', str(job_status['results'])
        results = GET('/plugin/id/syncthing/')
        assert results.json()['state'] == 'down', results.text

    def test_20_start_syncthing_jail(request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        payload = "syncthing"
        results = POST('/jail/start/', payload)
        assert results.status_code == 200, results.text
        job_status = wait_on_job(results.json(), 60)
        assert job_status['state'] == 'SUCCESS', str(job_status['results'])
        results = GET('/plugin/id/syncthing/')
        assert results.json()['state'] == 'up', results.text

    def test_21_stop_syncthing_jail_before_deleteing(request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        payload = {
            "jail": "syncthing",
            "force": True
        }
        results = POST('/jail/stop/', payload)
        assert results.status_code == 200, results.text
        job_status = wait_on_job(results.json(), 60)
        assert job_status['state'] == 'SUCCESS', str(job_status['results'])
        results = GET('/plugin/id/syncthing/')
        assert results.json()['state'] == 'down', results.text

    def test_22_delete_syncthing_plugin(request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        results = DELETE('/plugin/id/syncthing/')
        assert results.status_code == 200, results.text

    def test_23_looking_syncthing_jail_id_is_delete(request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        results = GET('/jail/id/syncthing/')
        assert results.status_code == 404, results.text

    def test_24_looking_syncthing_plugin_id_is_delete(request):
        depends(request, ["ADD_SYNCTHING_PLUGIN"])
        results = GET('/plugin/id/syncthing/')
        assert results.status_code == 404, results.text

    def test_25_get_list_of_available_plugins_job_id(request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        global job_results
        payload = {
            "plugin_repository": repos_url,
            "branch": plugins_branch
        }
        results = POST('/plugin/available/', payload)
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), int), results.text
        job_status = wait_on_job(results.json(), 180)
        assert job_status['state'] == 'SUCCESS', str(job_status['results'])
        job_results = job_status['results']

    @pytest.mark.parametrize('plugin', plugin_list)
    def test_26_verify_available_plugin_(plugin, request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        assert isinstance(job_results['result'], list), str(job_results)
        assert plugin in [p['plugin'] for p in job_results['result']], str(job_results['result'])

    @pytest.mark.parametrize('prop', ['version', 'revision', 'epoch'])
    def test_27_verify_available_plugins_transmission_is_not_na_(prop, request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        for plugin_info in job_results['result']:
            if 'transmission' in plugin_info['plugin']:
                break
        assert plugin_info[prop] != 'N/A', str(job_results)

    @pytest.mark.timeout(1200)
    @pytest.mark.dependency(name="ADD_TRANSMISSION_PLUGINS")
    def test_28_add_transmission_plugins(request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        payload = {
            "plugin_name": "transmission",
            "jail_name": "transmission",
            'props': [
                'nat=1'
            ],
            "branch": plugins_branch,
            "plugin_repository": repos_url
        }
        results = POST('/plugin/', payload)
        assert results.status_code == 200, results.text
        job_status = wait_on_job(results.json(), 1200)
        assert job_status['state'] == 'SUCCESS', str(job_status['results'])

    def test_29_search_plugin_transmission_id(request):
        depends(request, ["ADD_TRANSMISSION_PLUGINS"])
        results = GET('/plugin/?id=transmission')
        assert results.status_code == 200, results.text
        assert len(results.json()) > 0, results.text

    def test_30_verify_transmission_plugin_id_exist(request):
        depends(request, ["ADD_TRANSMISSION_PLUGINS"])
        results = GET('/plugin/id/transmission/')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), dict), results.text

    def test_31_verify_the_transmission_jail_id_exist(request):
        depends(request, ["ADD_TRANSMISSION_PLUGINS"])
        results = GET('/jail/id/transmission/')
        assert results.status_code == 200, results.text

    def test_32_delete_transmission_jail(request):
        depends(request, ["ADD_TRANSMISSION_PLUGINS"])
        payload = {
            'force': True
        }
        results = DELETE('/jail/id/transmission/', payload)
        assert results.status_code == 200, results.text

    def test_33_verify_the_transmission_jail_id_is_delete(request):
        depends(request, ["ADD_TRANSMISSION_PLUGINS"])
        results = GET('/jail/id/transmission/')
        assert results.status_code == 404, results.text

    def test_34_verify_clean_call(request):
        depends(request, ["ACTIVATE_JAIL_POOL"])
        results = POST('/jail/clean/', 'ALL')
        assert results.status_code == 200, results.text
        assert results.json() is True, results.text
