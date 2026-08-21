from middlewared.utils import osc, run

# OpenZFS 2.2+ renamed ZFS sysctls from underscore to dotted hierarchy.
# Users may have old-style names stored in the database from FreeBSD 13.
ZFS_SYSCTL_RENAMES = {
    'vfs.zfs.arc_free_target': 'vfs.zfs.arc.free_target',
    'vfs.zfs.arc_max': 'vfs.zfs.arc.max',
    'vfs.zfs.arc_min': 'vfs.zfs.arc.min',
    'vfs.zfs.arc_no_grow_shift': 'vfs.zfs.arc.no_grow_shift',
    'vfs.zfs.l2arc_feed_again': 'vfs.zfs.l2arc.feed_again',
    'vfs.zfs.l2arc_feed_min_ms': 'vfs.zfs.l2arc.feed_min_ms',
    'vfs.zfs.l2arc_feed_secs': 'vfs.zfs.l2arc.feed_secs',
    'vfs.zfs.l2arc_headroom': 'vfs.zfs.l2arc.headroom',
    'vfs.zfs.l2arc_headroom_boost': 'vfs.zfs.l2arc.headroom_boost',
    'vfs.zfs.l2arc_norw': 'vfs.zfs.l2arc.norw',
    'vfs.zfs.l2arc_noprefetch': 'vfs.zfs.l2arc.noprefetch',
    'vfs.zfs.l2arc_write_boost': 'vfs.zfs.l2arc.write_boost',
    'vfs.zfs.l2arc_write_max': 'vfs.zfs.l2arc.write_max',
    'vfs.zfs.max_auto_ashift': 'vfs.zfs.vdev.max_auto_ashift',
    'vfs.zfs.min_auto_ashift': 'vfs.zfs.vdev.min_auto_ashift',
    'vfs.zfs.prefetch_disable': 'vfs.zfs.prefetch.disable',
    'vfs.zfs.top_maxinflight': 'vfs.zfs.vdev.max_active',
    'vfs.zfs.zfetch.hole_shift': 'vfs.zfs.prefetch.hole_shift',
    'vfs.zfs.zfetch.max_distance': 'vfs.zfs.prefetch.max_distance',
    'vfs.zfs.zfetch.max_idistance': 'vfs.zfs.prefetch.max_idistance',
    'vfs.zfs.zfetch.max_reorder': 'vfs.zfs.prefetch.max_reorder',
    'vfs.zfs.zfetch.max_sec_reap': 'vfs.zfs.prefetch.max_sec_reap',
    'vfs.zfs.zfetch.max_streams': 'vfs.zfs.prefetch.max_streams',
    'vfs.zfs.zfetch.min_distance': 'vfs.zfs.prefetch.min_distance',
    'vfs.zfs.zfetch.min_sec_reap': 'vfs.zfs.prefetch.min_sec_reap',
}


def translate_sysctl_name(var):
    """Translate old-style ZFS sysctl names to OpenZFS 2.2+ dotted hierarchy.

    Returns the new dotted name if the old underscore name is given.
    The caller should try the returned name first, and fall back to the
    original name if the sysctl does not exist on this kernel version.
    """
    return ZFS_SYSCTL_RENAMES.get(var, var)


async def _resolve_sysctl_name(var, middleware):
    """Try the given sysctl name; if it fails and was translated, fall back to original."""
    cp = await run(['sysctl', var], check=False, encoding='utf8')
    if cp.returncode == 0:
        return var, cp
    return None, cp


async def sysctl_configuration(middleware):
    default_sysctl_config = await middleware.call('tunable.default_sysctl_config')
    for tunable in await middleware.call('tunable.query', [['type', '=', 'SYSCTL']]):
        original_var = tunable['var']
        var = translate_sysctl_name(original_var)
        if var != original_var:
            middleware.logger.info(
                'Translated legacy sysctl name %r -> %r', original_var, var
            )

        # Try new name first; if it doesn't exist, fall back to original
        resolved, _ = await _resolve_sysctl_name(var, middleware)
        if resolved is None and var != original_var:
            middleware.logger.info(
                'New sysctl name %r not found, falling back to %r', var, original_var
            )
            resolved, _ = await _resolve_sysctl_name(original_var, middleware)
            if resolved:
                var = original_var

        value_default = default_sysctl_config.get(var)
        if tunable['enabled']:
            if not value_default:
                cp = await run(['sysctl', var], check=False, encoding='utf8')
                if cp.returncode:
                    middleware.logger.error(
                        'Failed to get default value of %r : %s', var, cp.stderr.strip()
                    )
                else:
                    value_default = default_sysctl_config[var] = cp.stdout.split(
                        '=' if osc.IS_LINUX else ':'
                    )[-1].strip()
                    await middleware.call('tunable.set_default_value', var, value_default)
            cp = await run(['sysctl', f'{var}={tunable["value"]}'], check=False, encoding='utf8')
            if cp.returncode:
                middleware.logger.error(
                    'Failed to set sysctl %r -> %r : %s', var, tunable['value'], cp.stderr.strip()
                )
        elif value_default:
            cp = await run(['sysctl', f'{var}={value_default}'], check=False, encoding='utf8')
            if cp.returncode:
                middleware.logger.error(
                    'Failed to set sysctl %r -> %r : %s', var, tunable['value'], cp.stderr.strip()
                )


async def render(service, middleware):
    await sysctl_configuration(middleware)
