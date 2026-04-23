# -*- mode: python ; coding: utf-8 -*-

import importlib.util
from pathlib import Path

from PyInstaller.utils.hooks import collect_dynamic_libs, collect_submodules


project_root = Path(SPECPATH)
rules_dir = project_root / "rules"
assets_dir = project_root / "assets"
native_helper_dir = project_root / "native_helper" / "publish"
version_file = project_root / "ragnar_version_info.py"

version_spec = importlib.util.spec_from_file_location("ragnar_version_info", version_file)
version_module = importlib.util.module_from_spec(version_spec)
assert version_spec is not None and version_spec.loader is not None
version_spec.loader.exec_module(version_module)
VERSION_INFO = version_module.VERSION_INFO

hiddenimports = []
hiddenimports += collect_submodules("watchdog")
hiddenimports += collect_submodules("yara")

binaries = []
binaries += collect_dynamic_libs("yara")

datas = [
    (str(rules_dir), "rules"),
    (str(assets_dir), "assets"),
]
if native_helper_dir.exists():
    datas.append((str(native_helper_dir), "native_helper"))

a = Analysis(
    ["main.py"],
    pathex=[str(project_root)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="RagnarProtect",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    icon=str(assets_dir / "ragnar_protect.ico"),
    version=VERSION_INFO,
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
