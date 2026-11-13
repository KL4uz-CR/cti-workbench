from pathlib import Path, PureWindowsPath
from PyInstaller.utils.hooks import collect_all, copy_metadata

root = Path(SPECPATH).parent
icon = root / "assets" / "cti-workbench.ico"
datas, binaries, hiddenimports = collect_all("keyring")
datas += copy_metadata("iocinfo")
datas += [(str(icon), "assets"), (str(root / "src" / "translations.json"), "src")]

a = Analysis(
    [str(root / "src" / "main.py")],
    pathex=[str(root / "src")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
)
# Qt uses the Windows ICU ABI. A PATH entry can supply an incompatible ICU.
a.binaries = [
    entry for entry in a.binaries
    if PureWindowsPath(entry[0]).name.lower() not in {"icu.dll", "icuuc.dll", "icuin.dll"}
]

exe = EXE(PYZ(a.pure), a.scripts, a.binaries, a.datas, [],
          name="CTI-Workbench", console=False, icon=str(icon))
