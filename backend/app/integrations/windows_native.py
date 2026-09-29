"""Read Windows Event Log via Wevtapi with bookmarks; never spawn a shell."""

import ctypes
import sys
import time
from ctypes import wintypes

from app.core.errors import DomainError


def last_error() -> int:
    return int(getattr(ctypes, "get_last_error")())  # noqa: B009 - Windows-only ctypes export.


class NativeEventLog:
    api: ctypes.CDLL

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise DomainError(
                "Live Windows event collection requires Windows; use --fixture elsewhere"
            )
        self.api = ctypes.WinDLL("wevtapi", use_last_error=True)
        signatures = {
            "EvtQuery": (
                [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD],
                wintypes.HANDLE,
            ),
            "EvtNext": (
                [
                    wintypes.HANDLE,
                    wintypes.DWORD,
                    ctypes.POINTER(wintypes.HANDLE),
                    wintypes.DWORD,
                    wintypes.DWORD,
                    ctypes.POINTER(wintypes.DWORD),
                ],
                wintypes.BOOL,
            ),
            "EvtCreateBookmark": ([wintypes.LPCWSTR], wintypes.HANDLE),
            "EvtUpdateBookmark": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            "EvtSeek": (
                [
                    wintypes.HANDLE,
                    ctypes.c_longlong,
                    wintypes.HANDLE,
                    wintypes.DWORD,
                    wintypes.DWORD,
                ],
                wintypes.BOOL,
            ),
            "EvtRender": (
                [
                    wintypes.HANDLE,
                    wintypes.HANDLE,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    wintypes.LPVOID,
                    ctypes.POINTER(wintypes.DWORD),
                    ctypes.POINTER(wintypes.DWORD),
                ],
                wintypes.BOOL,
            ),
            "EvtClose": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result

    @staticmethod
    def failure() -> DomainError:
        code = last_error()
        return DomainError(
            f"Windows Event Log error {code}; check channel access "
            "or explicitly recover a stale bookmark",
            503,
            "windows_event_log",
        )

    def render(self, handle: int, flag: int) -> str:
        used, count = wintypes.DWORD(), wintypes.DWORD()
        self.api.EvtRender(None, handle, flag, 0, None, ctypes.byref(used), ctypes.byref(count))
        if last_error() != 122 or not 0 < used.value <= 131_072:
            raise self.failure()
        buffer = ctypes.create_unicode_buffer((used.value // ctypes.sizeof(ctypes.c_wchar)) + 1)
        if not self.api.EvtRender(
            None, handle, flag, used, buffer, ctypes.byref(used), ctypes.byref(count)
        ):
            raise self.failure()
        return buffer.value

    def read(self, channel: str, bookmark_xml: str | None, limit: int) -> list[tuple[str, str]]:
        query = self.api.EvtQuery(None, channel, "*", 1 | 0x100)
        if not query:
            raise self.failure()
        bookmark = self.api.EvtCreateBookmark(bookmark_xml)
        if not bookmark:
            self.api.EvtClose(query)
            raise self.failure()
        try:
            # Strict bookmark positioning reports cleared/overwritten logs instead of skipping them.
            if bookmark_xml and not self.api.EvtSeek(query, 1, bookmark, 0, 4 | 0x10000):
                raise self.failure()
            output: list[tuple[str, str]] = []
            deadline = time.monotonic() + 10
            for _ in range(limit):
                if time.monotonic() >= deadline:
                    break
                handles = (wintypes.HANDLE * 1)()
                returned = wintypes.DWORD()
                if not self.api.EvtNext(query, 1, handles, 1000, 0, ctypes.byref(returned)):
                    if last_error() == 259:
                        break
                    raise self.failure()
                handle = handles[0]
                if handle is None:
                    raise self.failure()
                try:
                    xml = self.render(handle, 1)
                    if not self.api.EvtUpdateBookmark(bookmark, handle):
                        raise self.failure()
                    output.append((xml, self.render(bookmark, 2)))
                finally:
                    self.api.EvtClose(handle)
            return output
        finally:
            self.api.EvtClose(bookmark)
            self.api.EvtClose(query)
