from middlewared.alert.base import (
    Alert,
    AlertCategory,
    AlertClass,
    AlertLevel,
    OneShotAlertClass,
    SimpleOneShotAlertClass,
)


class ApplicationsRuntimeSetupFailedAlertClass(AlertClass, SimpleOneShotAlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.WARNING
    title = 'Applications Runtime Setup Failed'
    text = (
        'Native Applications could not prepare its pool, Podman configuration, '
        'or packet-filter prerequisites. Managed workloads were not started.'
    )


class ApplicationsCertificateRenderFailedAlertClass(AlertClass, OneShotAlertClass):
    """the internal development record: the certificate an application mounts could not be written."""
    category = AlertCategory.SYSTEM
    level = AlertLevel.WARNING
    title = 'Application Certificate Could Not Be Mounted'
    text = (
        'The certificates mounted into application %(application)r could not be '
        'written: %(error)s. A running application keeps the files it already had; '
        'it cannot be started again until this is resolved.'
    )

    deleted_automatically = False

    async def create(self, args):
        return Alert(self.__class__, args, key=args['application'])

    async def delete(self, alerts, query):
        return [alert for alert in alerts if alert.args['application'] != query]


class ApplicationsCertificateRestartFailedAlertClass(AlertClass, OneShotAlertClass):
    """the internal development record: the renewed files are in place, the restart was not."""
    category = AlertCategory.SYSTEM
    level = AlertLevel.WARNING
    title = 'Application Did Not Restart After A Certificate Change'
    text = (
        'Application %(application)r was not restarted after its certificate changed: '
        '%(error)s. The new certificate is in place; restart the application to use it.'
    )

    deleted_automatically = False

    async def create(self, args):
        return Alert(self.__class__, args, key=args['application'])

    async def delete(self, alerts, query):
        return [alert for alert in alerts if alert.args['application'] != query]
