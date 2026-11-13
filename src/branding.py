"""CTI Workbench application mark."""
import sys
from pathlib import Path

from PySide6.QtGui import QIcon


def app_icon() -> QIcon:
    root = Path(sys._MEIPASS) if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
    return QIcon(str(root / "assets" / "cti-workbench.ico"))
