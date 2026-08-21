import datetime

from middlewared.alert.base import AlertClass, AlertCategory, AlertLevel, Alert, ThreadedAlertSource
from middlewared.alert.schedule import IntervalSchedule

WEBUI_SUPPORT_FORM = 'Please contact iXsystems Support using the form in System -> Support'


class OldBiosVersionAlertClass(AlertClass):
    category = AlertCategory.HARDWARE
    level = AlertLevel.WARNING
    title = 'Old BIOS Version'
    text = f'This system is running an old BIOS version. {WEBUI_SUPPORT_FORM}'
    products = ('ENTERPRISE',)
    proactive_support = True


class NVDIMMAndBIOSAlertSource(ThreadedAlertSource):
    schedule = IntervalSchedule(datetime.timedelta(minutes=5))
    products = ('ENTERPRISE',)

    def check_sync(self):
        alerts = []
        sys = ('TRUENAS-M40', 'TRUENAS-M50', 'TRUENAS-M60')
        if self.middleware.call_sync('truenas.get_chassis_hardware').startswith(sys):
            if self.middleware.call_sync('mseries.bios.is_old_version'):
                alerts.append(Alert(OldBiosVersionAlertClass))

        return alerts
