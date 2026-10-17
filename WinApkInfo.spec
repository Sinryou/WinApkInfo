# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包定义。

构建脚本 build.ps1 会设置以下环境变量：
    WINAPKINFO_VERSION       版本号（默认从 version.py 读取）
    WINAPKINFO_VERSION_FILE  生成的 Windows 文件属性文件
    WINAPKINFO_MODE          onedir / onefile
    WINAPKINFO_AAPT2         要随包携带的 aapt2.exe 绝对路径

也可以手动执行：
    python -m PyInstaller --noconfirm --clean WinApkInfo.spec
"""

import os
import re
from pathlib import Path

PROJECT_ROOT = Path(SPECPATH).resolve()
APP_NAME = "WinApkInfo"


def _read_version() -> str:
    version = os.environ.get("WINAPKINFO_VERSION", "").strip()
    if version:
        return version
    version_py = PROJECT_ROOT / "version.py"
    match = re.search(
        r'^__version__\s*=\s*["\']([^"\']+)["\']',
        version_py.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not match:
        raise SystemExit("无法从 version.py 读取版本号")
    return match.group(1)


VERSION = _read_version()
MODE = os.environ.get("WINAPKINFO_MODE", "onedir").strip().lower()
if MODE not in ("onedir", "onefile"):
    raise SystemExit("WINAPKINFO_MODE 只能是 onedir 或 onefile")

VERSION_FILE = os.environ.get("WINAPKINFO_VERSION_FILE", "").strip() or None
AAPT2_PATH = os.environ.get("WINAPKINFO_AAPT2", "").strip()

datas = [
    # local_resource_path() 以 sys._MEIPASS 为根，resources/ 必须保持同名目录
    (str(PROJECT_ROOT / "resources"), "resources"),
]
if AAPT2_PATH:
    aapt2 = Path(AAPT2_PATH)
    if not aapt2.is_file():
        raise SystemExit(f"WINAPKINFO_AAPT2 指向的文件不存在：{aapt2}")
    # find_aapt2() 会在 _MEIPASS/aapt2.exe 找到它（onedir 下即 _internal/）
    datas.append((str(aapt2), "."))

a = Analysis(
    [str(PROJECT_ROOT / "main.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    excludes=[
        "tkinter",
        "yaml",
        "numpy",
        "PyQt6.QtPdf",
        "PyQt6.QtPdfWidgets",
        "PyQt6.QtNetwork",
        "PyQt6.QtQml",
        "PyQt6.QtQuick",
        "PyQt6.QtQuickWidgets",
        "PyQt6.QtSql",
        "PyQt6.QtTest",
        "PyQt6.QtXml",
        "PyQt6.QtBluetooth",
        "PyQt6.QtNfc",
        "PyQt6.QtPositioning",
        "PyQt6.QtSensors",
        "PyQt6.QtSerialPort",
        "PyQt6.QtWebChannel",
        "PyQt6.QtWebSockets",
    ],
)

# 排除未使用的 Qt 动态库，进一步削减体积
_EXCLUDED_BINARIES = {"qt6pdf.dll", "qt6network.dll"}
a.binaries = [x for x in a.binaries if Path(x[0]).name.lower() not in _EXCLUDED_BINARIES]

pyz = PYZ(a.pure)

exe_options = dict(
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(PROJECT_ROOT / "resources" / "logo.ico"),
    version=VERSION_FILE,
)

if MODE == "onefile":
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        **exe_options,
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        **exe_options,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        name=APP_NAME,
    )
