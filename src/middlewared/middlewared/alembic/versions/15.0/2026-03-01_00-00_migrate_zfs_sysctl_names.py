"""Migrate old-style ZFS sysctl names to OpenZFS 2.2+ dotted hierarchy

OpenZFS 2.2+ (used in FreeBSD 15) renamed ZFS sysctls from underscore
to dotted hierarchy (e.g. vfs.zfs.arc_max -> vfs.zfs.arc.max).
Update any stored tunables so the UI shows correct names and
sysctl_config.py doesn't have to translate them at every boot.

Revision ID: a1b2c3d4e5f6
Revises: b412304844e1
Create Date: 2026-03-01 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = 'a1b2c3d4e5f6'
down_revision = 'b412304844e1'
branch_labels = None
depends_on = None

# Old underscore name -> new dotted name
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


def upgrade():
    conn = op.get_bind()
    for old_name, new_name in ZFS_SYSCTL_RENAMES.items():
        conn.execute(
            sa.text(
                'UPDATE system_tunable SET tun_var = :new_name WHERE tun_var = :old_name'
            ).bindparams(new_name=new_name, old_name=old_name)
        )


def downgrade():
    conn = op.get_bind()
    for old_name, new_name in ZFS_SYSCTL_RENAMES.items():
        conn.execute(
            sa.text(
                'UPDATE system_tunable SET tun_var = :old_name WHERE tun_var = :new_name'
            ).bindparams(old_name=old_name, new_name=new_name)
        )
