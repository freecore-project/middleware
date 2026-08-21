# Stub module for freenasOS — the original C library does not exist on FreeBSD 15.
# Provides the same top-level API surface so the middleware can import without
# crashing.  All functional calls raise NotImplementedError until a real update
# system is implemented for FreeBSD 15.

from . import Configuration, Manifest, Train, Update, Exceptions  # noqa: F401
