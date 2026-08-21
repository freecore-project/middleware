import platform

SYSTEM = platform.system().upper()
IS_FREEBSD = SYSTEM == "FREEBSD"
IS_LINUX = SYSTEM == "LINUX"

KNOWN_PLATFORMS = {"FREEBSD", "LINUX"}
if SYSTEM not in KNOWN_PLATFORMS:
    raise RuntimeError(
        f"Unsupported platform: {SYSTEM!r}. "
        f"Expected one of: {', '.join(sorted(KNOWN_PLATFORMS))}"
    )

if IS_FREEBSD:
    from .freebsd import *  # noqa

if IS_LINUX:
    from .linux import *  # noqa
