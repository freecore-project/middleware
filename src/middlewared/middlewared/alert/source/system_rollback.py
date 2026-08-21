from middlewared.alert.base import AlertCategory, AlertClass, AlertLevel, SimpleOneShotAlertClass


class SystemRollbackCaptureFailedAlertClass(AlertClass, SimpleOneShotAlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.WARNING
    title = 'Automatic Rollback Window Was Not Captured'
    text = (
        'FreeCORE could not capture the pre-upgrade system and jail state, so automatic rollback is not '
        'available for this upgrade. See the middleware log for the cause.'
    )
