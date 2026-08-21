"""Warn before middlewared runs out of descriptor headroom (the internal development record).

A TrueNAS CORE 13.3-U1.2 middlewared once reached 1306 open descriptors; past 1024 every jail start
and stop failed with "filedescriptor out of range in select()" until the daemon was restarted. The
select() caller in iocage is fixed (the internal development record), but nothing said the daemon was growing. This
check runs in the daemon itself, with the other alert sources, and costs one descriptor count a minute.
"""
import resource

import psutil

from middlewared.alert.base import Alert, AlertCategory, AlertClass, AlertLevel, ThreadedAlertSource

# select() cannot watch a descriptor numbered 1024 or higher, whatever the process limit is, so the
# headroom that matters is to 1024 or to the process's own soft limit, whichever comes first.
SELECT_WALL = 1024
HEADROOM = 0.75


def descriptor_wall(soft_limit):
    return SELECT_WALL if soft_limit in (resource.RLIM_INFINITY, -1) else min(SELECT_WALL, soft_limit)


def descriptor_threshold(soft_limit):
    return int(descriptor_wall(soft_limit) * HEADROOM)


class MiddlewaredDescriptorsAlertClass(AlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.WARNING
    title = "The Middleware Holds Many Open Files"
    text = ("The middleware process holds %(count)d open files, more than %(threshold)d. Near %(wall)d, "
            "operations that wait on files, such as starting or stopping a jail, begin to fail. Generate a "
            "debug (System > Advanced > Save Debug) and report it on the FreeCORE issue tracker; restarting "
            "the middleware ('service middlewared restart') releases the files.")

    products = ("CORE",)


class MiddlewaredDescriptorsAlertSource(ThreadedAlertSource):
    products = ("CORE",)

    def check_sync(self):
        soft_limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        threshold = descriptor_threshold(soft_limit)
        count = psutil.Process().num_fds()
        if count > threshold:
            return Alert(MiddlewaredDescriptorsAlertClass, {
                'count': count, 'threshold': threshold, 'wall': descriptor_wall(soft_limit),
            })
