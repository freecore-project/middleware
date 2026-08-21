def Avatar():
    return 'TrueNAS'


def ListClones():
    return []


def PendingUpdates(path=None):
    return None


def PendingUpdatesChanges(path=None):
    return {}


def ApplyUpdate(location, install_handler=None):
    raise NotImplementedError('freenasOS update system is not available on FreeBSD 15')


def ExtractFrozenUpdate(path, dest, verbose=False):
    raise NotImplementedError('freenasOS update system is not available on FreeBSD 15')


def DownloadUpdate(train, location, check_handler=None, get_handler=None):
    raise NotImplementedError('freenasOS update system is not available on FreeBSD 15')


def CheckForUpdates(train=None, cache_dir=None, diff_handler=None, handler=None):
    return None


def GetServiceDescription(service):
    return service
