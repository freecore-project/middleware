# alertclasses.update: bad class entries are validation errors, not tracebacks, and an
# update that omits `classes` leaves the saved alert settings alone.
from unittest.mock import AsyncMock

import pytest

from middlewared.alert.source.quota import QuotaWarningAlertClass  # noqa: F401 (registers the class)
from middlewared.alert.source.volume_status import VolumeStatusAlertClass  # noqa: F401 (registers the class)
from middlewared.plugins.alert import AlertClassesService
from middlewared.service import ValidationErrors

SAVED = {"QuotaWarning": {"policy": "DAILY"}, "VolumeStatus": {"level": "EMERGENCY", "proactive_support": True}}


class FakeMiddleware(dict):
    async def call(self, method, *args):
        return await self[method](*args)


def alertclasses():
    middleware = FakeMiddleware()
    config = {"id": 1, "classes": {k: dict(v) for k, v in SAVED.items()}}
    middleware["datastore.config"] = AsyncMock(return_value=config)
    middleware["datastore.update"] = AsyncMock()
    return AlertClassesService(middleware), middleware


@pytest.mark.asyncio
async def test_update_without_classes_keeps_saved_settings():
    service, middleware = alertclasses()

    assert (await service.do_update({}))["classes"] == SAVED
    middleware["datastore.update"].assert_awaited_once_with("system.alertclasses", 1, {"id": 1, "classes": SAVED})


@pytest.mark.asyncio
async def test_empty_classes_still_restores_defaults():
    # The webui sends this when every override is put back to its default.
    service, middleware = alertclasses()

    assert (await service.do_update({"classes": {}}))["classes"] == {}
    middleware["datastore.update"].assert_awaited_once_with("system.alertclasses", 1, {"id": 1, "classes": {}})


@pytest.mark.asyncio
async def test_unknown_class_with_proactive_support_is_a_validation_error():
    service, middleware = alertclasses()

    with pytest.raises(ValidationErrors) as ve:
        await service.do_update({"classes": {"Bogus": {"proactive_support": True}}})

    assert [(e.attribute, e.errmsg) for e in ve.value.errors] == [
        ("alert_class_update.classes.Bogus", "This alert class does not exist"),
    ]
    middleware["datastore.update"].assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [None, 5, True, "foo", "level", "proactive_support", ["policy"]])
async def test_non_dict_class_settings_are_a_validation_error(value):
    service, middleware = alertclasses()

    with pytest.raises(ValidationErrors) as ve:
        await service.do_update({"classes": {"VolumeStatus": value}})

    assert [(e.attribute, e.errmsg) for e in ve.value.errors] == [
        ("alert_class_update.classes.VolumeStatus", "A dict was expected"),
    ]
    middleware["datastore.update"].assert_not_awaited()


@pytest.mark.asyncio
async def test_known_class_settings_are_still_validated():
    service, middleware = alertclasses()

    with pytest.raises(ValidationErrors) as ve:
        await service.do_update({"classes": {
            "QuotaWarning": {"policy": "SOMETIMES", "proactive_support": True},
            "VolumeStatus": {"level": "INFO", "proactive_support": False},
        }})

    assert [(e.attribute, e.errmsg) for e in ve.value.errors] == [
        ("alert_class_update.classes.QuotaWarning.policy", "Invalid choice: SOMETIMES"),
        ("alert_class_update.classes.QuotaWarning.proactive_support",
         "Proactive support is not supported by this alert class"),
    ]
    middleware["datastore.update"].assert_not_awaited()
