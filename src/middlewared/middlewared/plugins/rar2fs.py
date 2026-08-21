import os
import shlex

from middlewared.schema import accepts, Bool, Dict, Int, Str
from middlewared.service import CallError, SystemServiceService, ValidationErrors
import middlewared.sqlalchemy as sa
from middlewared.validators import Range


class Rar2fsModel(sa.Model):
    __tablename__ = 'services_rar2fs'

    id = sa.Column(sa.Integer(), primary_key=True)
    rar2fs_source = sa.Column(sa.String(1024), default='')
    rar2fs_mountpoint = sa.Column(sa.String(1024), default='/media')
    rar2fs_seek_length = sa.Column(sa.Integer(), default=0)
    rar2fs_allow_other = sa.Column(sa.Boolean(), default=True)
    rar2fs_create_mountpoint = sa.Column(sa.Boolean(), default=True)
    rar2fs_extra_options = sa.Column(sa.Text(), default='')


class Rar2fsService(SystemServiceService):

    class Config:
        service = 'rar2fs'
        datastore_prefix = 'rar2fs_'
        service_verb = 'restart'

    @accepts(Dict(
        'rar2fs_update',
        Str('source', empty=False),
        Str('mountpoint', empty=False),
        Int('seek_length', validators=[Range(min=0)]),
        Bool('allow_other'),
        Bool('create_mountpoint'),
        Str('extra_options', max_length=None),
        update=True,
    ))
    async def do_update(self, data):
        """
        Update rar2fs mount configuration.

        rar2fs exposes RAR archives from a source directory through a read-only
        FUSE mount. The service starts only when the configured source path
        exists; mountpoint creation is controlled by ``create_mountpoint``.
        """
        old = await self.config()
        new = old.copy()
        new.update(data)
        self._normalize_config(new)

        verrors = ValidationErrors()
        self._validate_path(new, 'source', verrors, allow_root=True)
        self._validate_path(new, 'mountpoint', verrors, allow_root=False)

        if not verrors:
            if new['source'] == new['mountpoint']:
                verrors.add('rar2fs_update.mountpoint', 'Mountpoint must be different from source.')
            elif self._path_contains(new['source'], new['mountpoint']):
                verrors.add('rar2fs_update.mountpoint', 'Mountpoint must not be inside the source directory.')
            elif self._path_contains(new['mountpoint'], new['source']):
                verrors.add('rar2fs_update.source', 'Source must not be inside the mountpoint.')

        try:
            self.extra_option_args(new)
        except ValueError as e:
            verrors.add('rar2fs_update.extra_options', str(e))

        if verrors:
            raise verrors

        was_running = await self._service_running()
        if was_running and await self.middleware.call('service.stop', 'rar2fs'):
            raise CallError('Failed to stop rar2fs before applying the new configuration.')

        await self.middleware.call(
            'datastore.update',
            'services.rar2fs',
            old['id'],
            new,
            {'prefix': self._config.datastore_prefix},
        )
        await self.middleware.call('etc.generate', 'rc')
        await self.middleware.call('etc.generate', 'rar2fs')

        if was_running and not await self.middleware.call('service.start', 'rar2fs'):
            raise CallError('The rar2fs service failed to start with the new configuration.')

        return await self.config()

    def _normalize_config(self, config):
        for key in ('source', 'mountpoint'):
            config[key] = (config.get(key) or '').strip()
            if config[key]:
                config[key] = os.path.normpath(config[key])

        config['extra_options'] = (config.get('extra_options') or '').strip()

    def _validate_path(self, config, key, verrors, allow_root):
        path = config[key]
        if not path:
            verrors.add(f'rar2fs_update.{key}', 'This field is required.')
            return

        if not os.path.isabs(path):
            verrors.add(f'rar2fs_update.{key}', 'Enter an absolute path.')
            return

        if not allow_root and path == '/':
            verrors.add(f'rar2fs_update.{key}', 'The root directory cannot be used as a mountpoint.')

    def _path_contains(self, parent, child):
        try:
            return os.path.commonpath([parent, child]) == parent and parent != child
        except ValueError:
            return False

    def extra_option_args(self, config):
        try:
            args = shlex.split(config.get('extra_options') or '')
        except ValueError as e:
            raise ValueError(f'Unable to parse advanced options: {e}')

        for i, arg in enumerate(args):
            if arg == '--seek-length' or arg.startswith('--seek-length='):
                raise ValueError('Use Seek Length instead of passing --seek-length in advanced options.')
            if arg == '-o' and i + 1 < len(args) and 'allow_other' in args[i + 1].split(','):
                raise ValueError('Use Allow Other Users instead of passing allow_other in advanced options.')

        return args

    async def _service_running(self):
        service = await self.middleware.call(
            'service.query',
            [('service', '=', 'rar2fs')],
            {'get': True},
        )
        return service['state'] == 'RUNNING'
