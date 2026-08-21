import enum
import platform


class KRB5(enum.Enum):
    MIT = 1
    HEIMDAL = 2

    @staticmethod
    def platform():
        system = platform.system()
        if system == 'Linux':
            return KRB5.MIT

        # FreeBSD 14+ ships MIT Kerberos instead of Heimdal.
        if system == 'FreeBSD':
            try:
                if int(platform.release().split('.')[0]) >= 14:
                    return KRB5.MIT
            except (ValueError, IndexError):
                pass

        return KRB5.HEIMDAL
