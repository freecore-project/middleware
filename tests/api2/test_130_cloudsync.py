#!/usr/bin/env python3

import pytest
import sys
import os
import time
import urllib.parse
from pytest_dependency import depends
apifolder = os.getcwd()
sys.path.append(apifolder)
from functions import PUT, POST, GET, DELETE, SSH_TEST
from auto_config import pool_name, ip, password, user, dev_test

dataset = f"{pool_name}/cloudsync"
dataset_path = os.path.join("/mnt", dataset)

try:
    from config import (
        AWS_ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY,
        AWS_BUCKET
    )
except ImportError:
    Reason = 'AWS credential are missing in config.py'
    pytestmark = pytest.mark.skip(reason=Reason)
else:
    # comment pytestmark for development testing with --dev-test
    pytestmark = pytest.mark.skipif(dev_test, reason='Skip for testing')

# Lab fixture: an S3-compatible endpoint inside the QA estate replaces the
# external cloud account. When AWS_ENDPOINT is absent the credential payloads
# are exactly the inherited AWS shape.
try:
    from config import AWS_ENDPOINT
except ImportError:
    AWS_ENDPOINT = None


def s3_attributes(secret_access_key):
    attributes = {
        "access_key_id": AWS_ACCESS_KEY_ID,
        "secret_access_key": secret_access_key,
    }
    if AWS_ENDPOINT:
        attributes["endpoint"] = AWS_ENDPOINT
        attributes["skip_region"] = True
    return attributes


@pytest.fixture(scope='module')
def credentials():
    return {}


@pytest.fixture(scope='module')
def task():
    return {}


@pytest.fixture(scope='module')
def snapshot_task():
    return {}


def test_01_create_dataset(request):
    depends(request, ["pool_04"], scope="session")
    result = POST("/pool/dataset/", {"name": dataset})
    assert result.status_code == 200, result.text


def test_02_create_cloud_credentials(request, credentials):
    depends(request, ["pool_04"], scope="session")
    result = POST("/cloudsync/credentials/", {
        "name": "Test",
        "provider": "S3",
        "attributes": s3_attributes("garbage"),
    })
    assert result.status_code == 200, result.text
    credentials.update(result.json())


def test_03_update_cloud_credentials(request, credentials):
    depends(request, ["pool_04"], scope="session")
    result = PUT(f"/cloudsync/credentials/id/{credentials['id']}/", {
        "name": "Test",
        "provider": "S3",
        "attributes": s3_attributes(AWS_SECRET_ACCESS_KEY),
    })
    assert result.status_code == 200, result.text


def test_04_create_cloud_sync(request, credentials, task):
    depends(request, ["pool_04"], scope="session")
    result = POST("/cloudsync/", {
        "description": "Test",
        "direction": "PULL",
        "transfer_mode": "COPY",
        "path": dataset_path,
        "credentials": credentials["id"],
        "schedule": {
            "minute": "00",
            "hour": "00",
            "dom": "1",
            "month": "1",
            "dow": "1",
        },
        "attributes": {
            "bucket": AWS_BUCKET,
            "folder": "",
        },
        "args": "",
    })
    assert result.status_code == 200, result.text
    task.update(result.json())


def test_05_update_cloud_sync(request, credentials, task):
    depends(request, ["pool_04"], scope="session")
    result = PUT(f"/cloudsync/id/{task['id']}/", {
        "description": "Test",
        "direction": "PULL",
        "transfer_mode": "COPY",
        "path": dataset_path,
        "credentials": credentials["id"],
        "schedule": {
            "minute": "00",
            "hour": "00",
            "dom": "1",
            "month": "1",
            "dow": "1",
        },
        "attributes": {
            "bucket": AWS_BUCKET,
            "folder": "",
        },
        "args": "",
    })
    assert result.status_code == 200, result.text


def test_06_run_cloud_sync(request, task):
    depends(request, ["pool_04", "ssh_password"], scope="session")
    result = POST(f"/cloudsync/id/{task['id']}/sync/")
    assert result.status_code == 200, result.text
    for i in range(120):
        result = GET(f"/cloudsync/id/{task['id']}/")
        assert result.status_code == 200, result.text
        state = result.json()
        if state["job"] is None:
            time.sleep(1)
            continue
        if state["job"]["state"] in ["PENDING", "RUNNING"]:
            time.sleep(1)
            continue
        assert state["job"]["state"] == "SUCCESS", state
        cmd = f'cat {dataset_path}/freenas-test.txt'
        ssh_result = SSH_TEST(cmd, user, password, ip)
        assert ssh_result['result'] is True, ssh_result['output']
        assert ssh_result['output'] == 'freenas-test\n', ssh_result['output']
        return
    assert False, state


def test_07_restore_cloud_sync(request, task):
    depends(request, ["pool_04"], scope="session")
    result = POST(f"/cloudsync/id/{task['id']}/restore/", {
        "transfer_mode": "COPY",
        "path": dataset_path,
    })
    assert result.status_code == 200, result.text
    global restore_id
    restore_id = result.json()['id']


def test_08_delete_restore_cloudsync(request):
    depends(request, ["pool_04"], scope="session")
    result = DELETE(f"/cloudsync/id/{restore_id}/")
    assert result.status_code == 200, result.text


def test_09_create_cloud_sync_push_snapshot(request, credentials, snapshot_task):
    # PUSH with "Take Snapshot" is the only path that reaches get_dataset_recursive().
    # Every inherited case above is PULL, which is how the internal development record shipped
    # broken on every FreeCORE build with this suite green.
    depends(request, ["pool_04"], scope="session")
    result = POST("/cloudsync/", {
        "description": "Test snapshot",
        "direction": "PUSH",
        "transfer_mode": "COPY",
        "path": dataset_path,
        "credentials": credentials["id"],
        "snapshot": True,
        "schedule": {
            "minute": "00",
            "hour": "00",
            "dom": "1",
            "month": "1",
            "dow": "1",
        },
        "attributes": {
            "bucket": AWS_BUCKET,
            "folder": "freecore-mw400",
        },
        "args": "",
    })
    assert result.status_code == 200, result.text
    assert result.json()["snapshot"] is True, result.text
    snapshot_task.update(result.json())


def test_10_run_cloud_sync_push_snapshot(request, snapshot_task):
    # Dry run: rclone gets --dry-run, but that flag is appended before the snapshot
    # block, so the ZFS snapshot is still taken and the .zfs/snapshot source path still
    # computed -- the whole #400 surface runs, without writing to the bucket.
    depends(request, ["pool_04", "ssh_password"], scope="session")
    result = POST(f"/cloudsync/id/{snapshot_task['id']}/sync/", {"dry_run": True})
    assert result.status_code == 200, result.text
    for i in range(120):
        result = GET(f"/cloudsync/id/{snapshot_task['id']}/")
        assert result.status_code == 200, result.text
        state = result.json()
        if state["job"] is None:
            time.sleep(1)
            continue
        if state["job"]["state"] in ["PENDING", "RUNNING"]:
            time.sleep(1)
            continue
        # Pre-#400 this is EXCEPTION with KeyError: 'mountpoint' in the traceback.
        assert state["job"]["state"] == "SUCCESS", state
        return
    assert False, state


def test_11_cloud_sync_push_snapshot_is_cleaned_up(request):
    # cloud_sync.py deletes the temporary snapshot outside a finally, so a leaked
    # cloud_sync-* snapshot is a real failure mode, not housekeeping.
    depends(request, ["pool_04", "ssh_password"], scope="session")
    ssh_result = SSH_TEST(f"zfs list -H -t snapshot -o name -r {dataset}", user, password, ip)
    assert ssh_result['result'] is True, ssh_result['output']
    leftover = [line for line in ssh_result['output'].splitlines() if "@cloud_sync-" in line]
    assert leftover == [], leftover


def test_12_delete_cloud_sync_push_snapshot(request, snapshot_task):
    depends(request, ["pool_04"], scope="session")
    result = DELETE(f"/cloudsync/id/{snapshot_task['id']}/")
    assert result.status_code == 200, result.text


def test_96_delete_cloud_credentials_error(request, credentials):
    depends(request, ["pool_04"], scope="session")
    result = DELETE(f"/cloudsync/credentials/id/{credentials['id']}/")
    assert result.status_code == 422
    assert "This credential is used by cloud sync task" in result.json()["message"]


def test_97_delete_cloud_sync(request, task):
    depends(request, ["pool_04"], scope="session")
    result = DELETE(f"/cloudsync/id/{task['id']}/")
    assert result.status_code == 200, result.text


def test_98_delete_cloud_credentials(request, credentials):
    depends(request, ["pool_04"], scope="session")
    result = DELETE(f"/cloudsync/credentials/id/{credentials['id']}/")
    assert result.status_code == 200, result.text


def test_99_destroy_dataset(request):
    depends(request, ["pool_04"], scope="session")
    result = DELETE(f"/pool/dataset/id/{urllib.parse.quote(dataset, '')}/")
    assert result.status_code == 200, result.text
