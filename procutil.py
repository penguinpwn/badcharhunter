"""
procutil.py — find a running process's PID by its executable name.

The foundational primitive for automated respawn: after a service restarts, you
don't know its new PID, so you look it up by exe name and attach. Uses a Windows
Toolhelp snapshot to enumerate processes.

WINDOWS ONLY. Reuses the ctypes prototypes in win32.py.
"""

from __future__ import annotations
import ctypes

from . import win32 as w

# INVALID_HANDLE_VALUE is (HANDLE)-1.
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def find_pids_by_name(name: str) -> list[int]:
    """
    Return the PIDs of all running processes whose executable name matches
    `name` (case-insensitive; with or without the .exe is accepted). Empty list
    if none are found.
    """
    target = name.lower()
    target_alt = target if target.endswith(".exe") else target + ".exe"

    snap = w.kernel32.CreateToolhelp32Snapshot(w.TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        raise OSError(f"CreateToolhelp32Snapshot failed (err={w.last_error()})")

    pids: list[int] = []
    try:
        entry = w.PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(w.PROCESSENTRY32W)
        ok = w.kernel32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            exe = entry.szExeFile.lower()
            if exe == target or exe == target_alt:
                pids.append(entry.th32ProcessID)
            ok = w.kernel32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        w.kernel32.CloseHandle(snap)
    return pids


def find_pid_by_name(name: str) -> int:
    """
    Return exactly one PID for `name`. Raises if none found, or if several match
    (ambiguous — the caller should disambiguate, since attaching to the wrong
    instance would corrupt the hunt).
    """
    pids = find_pids_by_name(name)
    if not pids:
        raise LookupError(f"no running process named {name!r}")
    if len(pids) > 1:
        raise LookupError(
            f"{len(pids)} processes named {name!r} (pids {pids}); ambiguous — "
            "specify which, or ensure only one instance runs."
        )
    return pids[0]


if __name__ == "__main__":
    # Smoke test:
    #   python -m badcharhunter.procutil <exe_name>
    # e.g. python -m badcharhunter.procutil notepad.exe
    import sys
    if len(sys.argv) < 2:
        print("usage: procutil <exe_name>   e.g. procutil notepad.exe")
        raise SystemExit(1)
    name = sys.argv[1]
    pids = find_pids_by_name(name)
    if pids:
        print(f"[+] {name}: {len(pids)} match(es): {pids}")
    else:
        print(f"[-] no process named {name!r} found.")