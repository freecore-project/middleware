"""Add rar2fs service configuration

Revision ID: c5e7d2a9b041
Revises: a1b2c3d4e5f6
Create Date: 2026-06-01 00:00:00.000000+00:00

"""
from alembic import op
import os
import shlex
import sqlalchemy as sa


revision = 'c5e7d2a9b041'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None

# New native configurations default to scanning every volume of a RAR set.
# Migration must still preserve any seek length explicitly supplied by the
# operator's 13.3 post-init command.
DEFAULT_SEEK_LENGTH = 0


def parse_rar2fs_command(command):
    try:
        tokens = shlex.split(command or '')
    except ValueError:
        return None

    try:
        index = next(i for i, token in enumerate(tokens) if os.path.basename(token) == 'rar2fs')
    except StopIteration:
        return None

    args = tokens[index + 1:]
    positionals = []
    extra = []
    seek_length = DEFAULT_SEEK_LENGTH
    allow_other = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith('--seek-length='):
            try:
                seek_length = int(arg.split('=', 1)[1])
            except ValueError:
                seek_length = DEFAULT_SEEK_LENGTH
        elif arg == '--seek-length' and i + 1 < len(args):
            i += 1
            try:
                seek_length = int(args[i])
            except ValueError:
                seek_length = DEFAULT_SEEK_LENGTH
        elif arg == '-o' and i + 1 < len(args):
            i += 1
            options = [option for option in args[i].split(',') if option]
            if 'allow_other' in options:
                allow_other = True
                options = [option for option in options if option != 'allow_other']
            if options:
                extra.extend(['-o', ','.join(options)])
        elif arg.startswith('-') and len(positionals) >= 2:
            extra.append(arg)
        elif len(positionals) < 2:
            positionals.append(arg)
        else:
            extra.append(arg)
        i += 1

    if len(positionals) < 2:
        return None

    return {
        'source': os.path.normpath(positionals[0]),
        'mountpoint': os.path.normpath(positionals[1]),
        'seek_length': seek_length,
        'allow_other': allow_other,
        'extra_options': ' '.join(shlex.quote(arg) for arg in extra),
    }


def default_config(conn):
    config = {
        'source': '',
        'mountpoint': '/media',
        'seek_length': DEFAULT_SEEK_LENGTH,
        'allow_other': True,
        'create_mountpoint': True,
        'extra_options': '',
        'enabled': False,
        'legacy_script_id': None,
    }

    try:
        rows = conn.execute(sa.text(
            "SELECT id, ini_command, ini_enabled FROM tasks_initshutdown "
            "WHERE lower(ini_type) = 'command' AND lower(ini_when) = 'postinit' "
            "ORDER BY id"
        )).fetchall()
    except Exception:
        rows = []

    for row in rows:
        parsed = parse_rar2fs_command(row[1])
        if parsed is None:
            continue
        config.update(parsed)
        config['enabled'] = bool(row[2])
        config['legacy_script_id'] = row[0]
        break

    return config


def upgrade():
    op.create_table(
        'services_rar2fs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('rar2fs_source', sa.String(length=1024), nullable=False),
        sa.Column('rar2fs_mountpoint', sa.String(length=1024), nullable=False),
        sa.Column('rar2fs_seek_length', sa.Integer(), nullable=False),
        sa.Column('rar2fs_allow_other', sa.Boolean(), nullable=False),
        sa.Column('rar2fs_create_mountpoint', sa.Boolean(), nullable=False),
        sa.Column('rar2fs_extra_options', sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_services_rar2fs')),
    )

    config = default_config(op.get_bind())
    op.execute(
        sa.text(
            'INSERT INTO services_rar2fs ('
            'rar2fs_source, rar2fs_mountpoint, rar2fs_seek_length, rar2fs_allow_other, '
            'rar2fs_create_mountpoint, rar2fs_extra_options'
            ') VALUES ('
            ':source, :mountpoint, :seek_length, :allow_other, '
            ':create_mountpoint, :extra_options'
            ')'
        ).bindparams(
            source=config['source'],
            mountpoint=config['mountpoint'],
            seek_length=config['seek_length'],
            allow_other=config['allow_other'],
            create_mountpoint=config['create_mountpoint'],
            extra_options=config['extra_options'],
        )
    )
    op.execute(
        sa.text(
            "INSERT INTO services_services (srv_service, srv_enable) "
            "VALUES ('rar2fs', :enabled)"
        ).bindparams(enabled=config['enabled'])
    )

    if config['legacy_script_id'] is not None:
        op.execute(
            sa.text('UPDATE tasks_initshutdown SET ini_enabled = 0 WHERE id = :id').bindparams(
                id=config['legacy_script_id'],
            )
        )


def downgrade():
    op.execute("DELETE FROM services_services WHERE srv_service = 'rar2fs'")
    op.drop_table('services_rar2fs')
