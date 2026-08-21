# -*- coding=utf-8 -*-
import logging
import re
import subprocess

import sysctl

logger = logging.getLogger(__name__)

__all__ = ['get_cpu_model']


RE_PORT = re.compile(r'([0-9a-fA-Fx]+).*\((uart[0-9])+\)')


def get_cpu_model():
    return sysctl.filter('hw.model')[0].value


def serial_port_choices():
    try:
        cp = subprocess.run(
            ['/usr/sbin/devinfo', '-u'],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        logger.warning('Failed to run devinfo for serial port enumeration')
        return []
    return [
        {
            'name': e[1],
            'start': e[0],
        } for e in RE_PORT.findall(cp.stdout)
    ]
