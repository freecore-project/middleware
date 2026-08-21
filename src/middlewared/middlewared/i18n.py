from gettext import NullTranslations, GNUTranslations
from importlib.resources import files
import logging

logger = logging.getLogger(__name__)

translations = NullTranslations()


def set_language(language):
    global translations

    try:
        with open(files("middlewared").joinpath("locale", language, "LC_MESSAGES", "middlewared.mo"), "rb") as f:
            translations = GNUTranslations(f)

        return True
    except Exception as e:
        if language != "en":
            logger.warning("Failed to set language %r: %r", language, e)

        translations = NullTranslations()

        return False


def _(message):
    return translations.gettext(message)


def __(singular, plural, n):
    return translations.ngettext(singular, plural, n)
