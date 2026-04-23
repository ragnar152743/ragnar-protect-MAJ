import importlib.util
from pathlib import Path

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo,
    StringFileInfo,
    StringStruct,
    StringTable,
    VSVersionInfo,
    VarFileInfo,
    VarStruct,
)

version_path = Path(__file__).resolve().parent / "ragnar_protect" / "version.py"
version_spec = importlib.util.spec_from_file_location("ragnar_protect_version", version_path)
version_module = importlib.util.module_from_spec(version_spec)
assert version_spec is not None and version_spec.loader is not None
version_spec.loader.exec_module(version_module)
APP_VERSION = version_module.APP_VERSION
VERSION_TUPLE = version_module.VERSION_TUPLE


VERSION_INFO = VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=VERSION_TUPLE,
        prodvers=VERSION_TUPLE,
        mask=0x3F,
        flags=0x0,
        OS=0x40004,
        fileType=0x1,
        subtype=0x0,
        date=(0, 0),
    ),
    kids=[
        StringFileInfo(
            [
                StringTable(
                    "040904B0",
                    [
                        StringStruct("CompanyName", "Ragnar Labs"),
                        StringStruct("FileDescription", "Ragnar Protect Security Platform"),
                        StringStruct("FileVersion", ".".join(str(part) for part in VERSION_TUPLE)),
                        StringStruct("InternalName", "RagnarProtect"),
                        StringStruct("LegalCopyright", "Copyright (C) 2026 Ragnar Labs"),
                        StringStruct("OriginalFilename", "RagnarProtect.exe"),
                        StringStruct("ProductName", "Ragnar Protect"),
                        StringStruct("ProductVersion", APP_VERSION),
                    ],
                )
            ]
        ),
        VarFileInfo([VarStruct("Translation", [1033, 1200])]),
    ],
)
