#!/usr/bin/env python3

# Author: Eric Turgeon
# License: BSD

import pytest
import sys
import os
apifolder = os.getcwd()
sys.path.append(apifolder)
from functions import PUT, GET
from auto_config import dev_test
# comment pytestmark for development testing with --dev-test
pytestmark = pytest.mark.skipif(dev_test, reason='Skip for testing')


def test_01_Configuring_settings():
    payload = {"fromemail": "qa-noreply@freecore.local",
               "outgoingserver": "mail.freecore.local",
               "pass": "changeme",
               "port": 25,
               "security": "PLAIN",
               "smtp": True,
               "user": "qa-noreply@freecore.local"}
    results = PUT("/mail/", payload)
    assert results.status_code == 200, results.text


def test_02_look_fromemail_settings_change():
    results = GET("/mail/")
    assert results.json()["fromemail"] == "qa-noreply@freecore.local"


def test_03_look_outgoingserver_settings_change():
    results = GET("/mail/")
    assert results.json()["outgoingserver"] == "mail.freecore.local"


def test_04_look_pass_settings_change():
    results = GET("/mail/")
    assert results.json()["pass"] == "changeme"


def test_05_look_port_settings_change():
    results = GET("/mail/")
    assert results.json()["port"] == 25


def test_06_look_security_settings_change():
    results = GET("/mail/")
    assert results.json()["security"] == "PLAIN"


def test_07_look_smtp_settings_change():
    results = GET("/mail/")
    assert results.json()["smtp"] is True


def test_08_look_user_settings_change():
    results = GET("/mail/")
    assert results.json()["user"] == "qa-noreply@freecore.local"
