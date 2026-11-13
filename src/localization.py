"""Application locale selection and message lookup."""
import json
import sys
from pathlib import Path

from PySide6.QtCore import QLibraryInfo, QLocale, QSettings, QTranslator


LANGUAGES = {"en": "English", "es": "Español", "pt_BR": "Português (Brasil)"}
CATALOG_DIR = Path(sys._MEIPASS) / "src" if getattr(sys, "frozen", False) else Path(__file__).parent
CATALOG = json.loads((CATALOG_DIR / "translations.json").read_text(encoding="utf-8"))
_language = "en"


def settings():
    return QSettings(QSettings.Format.IniFormat, QSettings.Scope.UserScope, "CTI Workbench", "CTI Workbench")


def selected_language():
    locale = QLocale.system().name()
    default = "es" if locale.startswith("es") else "pt_BR" if locale.startswith("pt") else "en"
    language = settings().value("language", default)
    return language if language in LANGUAGES else default


def save_language(language):
    preferences = settings()
    preferences.setValue("language", language)
    preferences.sync()
    return preferences.status() == QSettings.Status.NoError


def initialize_language(app, language=None):
    global _language
    _language = language if language in LANGUAGES else selected_language()
    if _language != "en":
        translator = QTranslator(app)
        qt_catalog = Path(__file__).resolve().parent.parent / "assets" / "qt"
        qt_locale = "pt_BR" if _language == "pt_BR" else "es"
        if (translator.load(f"qtbase_{qt_locale}", str(qt_catalog)) or
                translator.load(f"qtbase_{qt_locale}", QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath))):
            app.installTranslator(translator)


def tr(message, **values):
    translated = CATALOG.get(message, {}).get(_language, message)
    return translated.format(**values) if values else translated
