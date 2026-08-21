class UpdateException(Exception):
    pass


class UpdateNetworkException(UpdateException):
    pass


class UpdateNetworkFileNotFoundException(UpdateNetworkException):
    pass


class UpdateIncompleteCacheException(Exception):
    pass


class UpdateInvalidCacheException(Exception):
    pass


class UpdateBusyCacheException(Exception):
    pass
