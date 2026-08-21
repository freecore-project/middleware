#!/usr/bin/env python3

import pytest
import sys
import os
import time
from pytest_dependency import depends
apifolder = os.getcwd()
sys.path.append(apifolder)
from functions import POST, GET, DELETE, SSH_TEST, send_file
from auto_config import ip, user, password, pool_name, ha
from auto_config import dev_test
reason = 'Skipping for test development'
# comment pytestmark for development testing with --dev-test
pytestmark = pytest.mark.skipif(dev_test, reason=reason)

dataset = f"{pool_name}/test_pool"
dataset_url = dataset.replace('/', '%2F')
dataset_path = os.path.join("/mnt", dataset)

IMAGES = {}
loops = {
    'msdosfs': '/dev/loop8',
    'msdosfs-nonascii': '/dev/loop9',
    'ntfs': '/dev/loop10'
}

# Exclude from HA testing
if not ha:
    def expect_state(job_id, state):
        for _ in range(60):
            job = GET(f"/core/get_jobs/?id={job_id}").json()[0]
            if job["state"] in ["WAITING", "RUNNING"]:
                time.sleep(1)
                continue
            if job["state"] == state:
                return job
            else:
                assert False, str(job)
        assert False, str(job)

    def test_01_create_dataset(request):
        depends(request, ["pool_04"], scope="session")
        result = POST("/pool/dataset/", {"name": dataset})
        assert result.status_code == 200, result.text

    @pytest.mark.parametrize('image', ["msdosfs", "msdosfs-nonascii", "ntfs"])
    def test_02_setup_function(request, image):
        depends(request, ["pool_04", "ssh_key"], scope="session")
        zf = os.path.join(os.path.dirname(__file__), "fixtures", f"{image}.gz")
        destination = f"/tmp/{image}.gz"
        send_results = send_file(zf, destination, user, None, ip)
        assert send_results['result'] is True, send_results['output']

        cmd = f"gunzip -f /tmp/{image}.gz"
        gunzip_results = SSH_TEST(cmd, user, password, ip)
        assert gunzip_results['result'] is True, gunzip_results['output']
        cmd = f"mdconfig -a -t vnode -f /tmp/{image}"
        mdconfig_results = SSH_TEST(cmd, user, password, ip)
        assert mdconfig_results['result'] is True, mdconfig_results['output']
        IMAGES[image] = f"/dev/{mdconfig_results['output'].strip()}s1"

    def test_03_import_msdosfs(request):
        depends(request, ["pool_04"], scope="session")
        payload = {
            "device": IMAGES['msdosfs'],
            "fs_type": "msdosfs",
            "fs_options": {},
            "dst_path": dataset_path,
        }
        results = POST("/pool/import_disk/", payload)
        assert results.status_code == 200, results.text
        job_id = results.json()
        expect_state(job_id, "SUCCESS")

    def test_04_look_if_Directory_slash_File(request):
        depends(request, ["pool_04", "ssh_password"], scope="session")
        cmd = f'test -f {dataset_path}/Directory/File'
        results = SSH_TEST(cmd, user, password, ip)
        assert results['result'] is True, f'out: {results["output"]}, err: {results["stderr"]}'

    def test_05_import_nonascii_msdosfs_fails(request):
        depends(request, ["pool_04", "ssh_password"], scope="session")
        results = SSH_TEST(
            f'rm -f {dataset_path}/Directory/File', user, password, ip
        )
        assert results['result'] is True, (
            f'out: {results["output"]}, err: {results["stderr"]}'
        )

        payload = {
            "device": IMAGES['msdosfs-nonascii'],
            "fs_type": "msdosfs",
            "fs_options": {},
            "dst_path": dataset_path,
        }
        results = POST("/pool/import_disk/", payload)
        assert results.status_code == 200, results.text

        job_id = results.json()

        job = expect_state(job_id, "FAILED")

        version_results = GET("/system/version/")
        assert version_results.status_code == 200, version_results.text
        version = version_results.json()

        # FreeBSD changed invalid msdosfs OPEN/DELETE lookups from EINVAL to
        # ENOENT in 0b2c159c8fa. Rsync therefore reports the same failed import
        # as a generic partial transfer (23) on 13.3 and a vanished source (24)
        # on FreeBSD 15. Keep both target contracts exact.
        if version.startswith("TrueNAS-13.3"):
            expected_error = "rsync failed with exit code 23"
        elif version.startswith("FreeCORE-15.0"):
            expected_error = "rsync failed with exit code 24"
        else:
            pytest.fail(
                f"Unclassified msdosfs import behavior for {version!r}"
            )

        assert job["error"] == expected_error, job

    def test_06_verify_failed_nonascii_import_state(request):
        depends(request, ["pool_04", "ssh_password"], scope="session")
        cmd = f'find {dataset_path} -mindepth 1 -print'
        results = SSH_TEST(cmd, user, password, ip)
        assert results['result'] is True, (
            f'out: {results["output"]}, err: {results["stderr"]}'
        )
        assert set(results['output'].splitlines()) == {
            f'{dataset_path}/Directory',
            f'{dataset_path}/Directory/File',
        }, results['output']

        import_path = os.path.join(
            "/var/run/importcopy/tmpdir",
            os.path.basename(IMAGES['msdosfs-nonascii']),
        )
        results = SSH_TEST(f'test ! -e {import_path}', user, password, ip)
        assert results['result'] is True, (
            f'out: {results["output"]}, err: {results["stderr"]}'
        )

    def test_07_import_nonascii_msdosfs(request):
        depends(request, ["pool_04"], scope="session")
        locale = 'ru_RU.UTF-8'
        payload = {
            "device": IMAGES['msdosfs-nonascii'],
            "fs_type": "msdosfs",
            "fs_options": {"locale": locale},
            "dst_path": dataset_path,
        }
        results = POST("/pool/import_disk/", payload)
        assert results.status_code == 200, results.text
        job_id = results.json()
        expect_state(job_id, "SUCCESS")

    def test_08_look_if_Каталог_slash_Файл(request):
        depends(request, ["pool_04", "ssh_password"], scope="session")
        cmd = f'test -f {dataset_path}/Каталог/Файл'
        results = SSH_TEST(cmd, user, password, ip)
        assert results['result'] is True, f'out: {results["output"]}, err: {results["stderr"]}'

    def test_09_import_ntfs(request):
        depends(request, ["pool_04"], scope="session")
        payload = {
            "device": IMAGES['ntfs'],
            "fs_type": "ntfs",
            "fs_options": {},
            "dst_path": dataset_path,
        }
        results = POST("/pool/import_disk/", payload)
        assert results.status_code == 200, results.text

        job_id = results.json()

        expect_state(job_id, "SUCCESS")

    def test_10_look_if_Каталог_slash_Файл(request):
        depends(request, ["pool_04", "ssh_password"], scope="session")
        cmd = f'test -f {dataset_path}/Каталог/Файл'
        results = SSH_TEST(cmd, user, password, ip)
        assert results['result'] is True, f'out: {results["output"]}, err: {results["stderr"]}'

    @pytest.mark.parametrize('image', ["msdosfs", "msdosfs-nonascii", "ntfs"])
    def test_11_stop_image_with_mdconfig(request, image):
        depends(request, ["pool_04", "ssh_password"], scope="session")
        cmd = f"mdconfig -d -u {IMAGES[image].replace('s1', '')}"
        results = SSH_TEST(cmd, user, password, ip)
        assert results['result'] is True, f'out: {results["output"]}, err: {results["stderr"]}'

        cmd = f"rm -fv /tmp/{image}.gz"
        gunzip_results = SSH_TEST(cmd, user, password, ip)
        assert gunzip_results['result'] is True, gunzip_results['output']

        cmd = f"rm -rfv /tmp/{image}"
        rm_results = SSH_TEST(cmd, user, password, ip)
        assert rm_results['result'] is True, rm_results['output']

    def test_12_delete_dataset(request):
        depends(request, ["pool_04"], scope="session")
        results = DELETE(f"/pool/dataset/id/{dataset_url}/")
        assert results.status_code == 200, results.text
