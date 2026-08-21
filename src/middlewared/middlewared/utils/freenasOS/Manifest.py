class Manifest:
    def __init__(self, require_signature=False):
        self._require_signature = require_signature

    def LoadPath(self, path):
        raise NotImplementedError('freenasOS is not available on FreeBSD 15')

    def Version(self):
        raise NotImplementedError('freenasOS is not available on FreeBSD 15')

    def Notice(self):
        return ''

    def Notes(self):
        return ''

    def Sequence(self):
        return ''

    def TimeStamp(self):
        return None
