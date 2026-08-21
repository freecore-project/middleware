# alertservice attribute errors are named `<schema>.attributes.<key>` whichever step rejects the value,
# and updating an alert service that does not exist says so instead of raising a bare MatchNotFound.
import asyncio
import errno
from unittest.mock import patch

import pytest

from middlewared.alert.service.mail import MailAlertService
from middlewared.plugins.alert import ALERT_SERVICES_FACTORIES, AlertServiceService
from middlewared.plugins.datastore.read import DatastoreService
from middlewared.schema import Schemas, resolve_methods
from middlewared.service_exception import ValidationError, ValidationErrors
from middlewared.utils import filter_list

ROW = {"id": 1, "name": "Mail", "type": "Mail", "attributes": {"email": ""}, "enabled": True, "level": "WARNING"}


class FakeMiddleware(dict):
    def __init__(self, rows):
        super().__init__()
        self.rows = rows
        self.updated = []
        self["datastore.query"] = self.datastore_query
        self["datastore.update"] = self.datastore_update

    def event_register(self, *args, **kwargs):
        pass

    async def call(self, method, *args):
        result = self[method](*args)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    async def datastore_query(self, name, filters, options):
        """`datastore.query` semantics over `rows`: `extend`, then filters and `get` (MatchNotFound)."""
        assert name == "system.alertservice"
        rows = [await self.call(options["extend"], dict(row)) for row in self.rows]
        return filter_list(rows, filters, {"get": options.get("get", False)})

    async def datastore_update(self, name, id, data):
        self.updated.append((name, id, dict(data)))


@pytest.fixture(autouse=True)
def alert_services_factories():
    # Filled by `alert.load` at runtime
    with patch.dict(ALERT_SERVICES_FACTORIES, {MailAlertService.name(): MailAlertService}):
        yield


def alertservice(rows):
    middleware = FakeMiddleware(rows)
    service = AlertServiceService(middleware)
    middleware["alertservice.query"] = service.query
    middleware["alertservice._extend"] = service._extend
    # `datastore.query` registers the `query-filters`/`query-options` schemas that `query` refers to
    resolve_methods(Schemas(), [DatastoreService.query, service.query, service.do_create, service.do_update])
    return service, middleware


@pytest.mark.asyncio
@pytest.mark.parametrize("email,errmsg", [
    (["root@localhost"], "Not a string"),
    ("x" * 1025, "Value greater than 1024 not allowed"),
], ids=["rejected-by-clean", "rejected-by-validate"])
async def test_attribute_errors_are_named_after_the_attribute(email, errmsg):
    service, _ = alertservice([])

    with pytest.raises(ValidationErrors) as ve:
        await service._validate({"type": "Mail", "attributes": {"email": email}}, "alert_service_create")

    assert [(e.attribute, e.errmsg) for e in ve.value.errors] == [("alert_service_create.attributes.email", errmsg)]


@pytest.mark.asyncio
async def test_update_of_a_missing_id_does_not_exist():
    service, middleware = alertservice([ROW])

    with pytest.raises(ValidationError) as ve:
        await service.do_update(99, {"enabled": False})

    assert ve.value.errno == errno.ENOENT
    assert ve.value.errmsg == "Alert Service 99 does not exist"
    assert middleware.updated == []


@pytest.mark.asyncio
async def test_update_of_an_existing_id():
    service, middleware = alertservice([ROW])

    result = await service.do_update(1, {"enabled": False})

    assert result == {**ROW, "enabled": False, "type__title": "Email"}
    assert middleware.updated == [("system.alertservice", 1, {**ROW, "enabled": False})]
