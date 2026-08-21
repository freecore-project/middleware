from middlewared.alert.base import SimpleOneShotAlertClass, AlertClass, AlertCategory, AlertLevel


class UPSBatteryLowAlertClass(AlertClass, SimpleOneShotAlertClass):
    category = AlertCategory.UPS
    level = AlertLevel.ALERT
    title = 'UPS Battery LOW'
    text = 'UPS %(ups)s battery level low.'


class UPSOnlineAlertClass(AlertClass, SimpleOneShotAlertClass):
    category = AlertCategory.UPS
    level = AlertLevel.INFO
    title = 'UPS On Line Power'
    text = 'UPS %(ups)s is on line power.'


class UPSOnBatteryAlertClass(AlertClass, SimpleOneShotAlertClass):
    category = AlertCategory.UPS
    level = AlertLevel.CRITICAL
    title = 'UPS On Battery'
    text = 'UPS %(ups)s is on battery power.'


class UPSCommbadAlertClass(AlertClass, SimpleOneShotAlertClass):
    category = AlertCategory.UPS
    level = AlertLevel.CRITICAL
    title = 'UPS Communication Lost'
    text = 'Communication with UPS %(ups)s lost.'


class UPSCommokAlertClass(AlertClass, SimpleOneShotAlertClass):
    category = AlertCategory.UPS
    level = AlertLevel.INFO
    title = 'UPS Communication Established'
    text = 'Communication with UPS %(ups)s established.'


class UPSServiceNotRunningAlertClass(AlertClass, SimpleOneShotAlertClass):
    # the internal development record: raised when the boot-time retry (#567) gives up.
    category = AlertCategory.UPS
    level = AlertLevel.CRITICAL
    title = 'UPS Service Is Not Running'
    text = (
        'The UPS service is enabled but is not running: UPS %(ups)s could not be reached after boot and the '
        'start retries have stopped. Until the service runs, this system is not protected by the UPS. Check the '
        'UPS connection, then start the UPS service.'
    )


class UPSReplbattAlertClass(AlertClass, SimpleOneShotAlertClass):
    category = AlertCategory.UPS
    level = AlertLevel.CRITICAL
    title = 'UPS Battery Needs Replacement'
    text = 'UPS %(ups)s Battery needs replacement.'
