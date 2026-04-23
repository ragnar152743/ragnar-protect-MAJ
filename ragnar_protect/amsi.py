from __future__ import annotations

import ctypes
import threading
from ctypes import wintypes


class AmsiScanner:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._available = False
        self._context = ctypes.c_void_p()
        self._dll = None
        try:
            self._dll = ctypes.WinDLL("amsi.dll")
            self._dll.AmsiInitialize.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
            self._dll.AmsiInitialize.restype = wintypes.HRESULT
            self._dll.AmsiUninitialize.argtypes = [ctypes.c_void_p]
            self._dll.AmsiUninitialize.restype = None
            self._dll.AmsiScanBuffer.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.ULONG,
                wintypes.LPCWSTR,
                ctypes.c_void_p,
                ctypes.POINTER(wintypes.ULONG),
            ]
            self._dll.AmsiScanBuffer.restype = wintypes.HRESULT
            self._dll.AmsiResultIsMalware.argtypes = [wintypes.ULONG]
            self._dll.AmsiResultIsMalware.restype = wintypes.BOOL

            result = self._dll.AmsiInitialize("Ragnar Protect", ctypes.byref(self._context))
            self._available = result == 0
        except Exception:
            self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def scan_bytes(self, data: bytes, content_name: str) -> dict[str, object]:
        if not self._available or not data:
            return {"available": False, "is_malware": False, "result": 0, "hresult": None}

        with self._lock:
            result = wintypes.ULONG(0)
            buffer = ctypes.create_string_buffer(data)
            hresult = self._dll.AmsiScanBuffer(
                self._context,
                ctypes.cast(buffer, ctypes.c_void_p),
                len(data),
                content_name,
                None,
                ctypes.byref(result),
            )
            is_malware = bool(self._dll.AmsiResultIsMalware(result.value)) if hresult == 0 else False
            return {
                "available": True,
                "is_malware": is_malware,
                "result": int(result.value),
                "hresult": int(hresult),
            }

    def scan_text(self, text: str, content_name: str) -> dict[str, object]:
        return self.scan_bytes(text.encode("utf-8", errors="ignore"), content_name)

    def close(self) -> None:
        if self._available and self._context:
            try:
                self._dll.AmsiUninitialize(self._context)
            except Exception:
                pass
            self._available = False

    def __del__(self) -> None:
        self.close()
