"""
manual_debugger.py — the process-and-events owner.

Role (and hard boundary): this file launches or attaches to a target, OWNS its
process handle, pumps the Windows debug-event loop, and reports crash state. It
does NOT send payloads, does NOT read or write memory, does NOT locate buffers,
does NOT diff or generate byte sets, and does NOT orchestrate the round loop.
Those belong to connection.py, attach_read/mem_write, the search module, the
tested core, and the driver respectively.

It imports only win32 (its own plumbing) and CrashSignature (a shared data type
it fills in and hands back). It calls no other logic file — other files use the
debugger, never the reverse.

Two entry points, converging to one shared event pump:

    launch(exe_path)  — CreateProcess with DEBUG_ONLY_THIS_PROCESS. We own the
                        target from birth and get a full-access handle. Respawn
                        is just launch() again.
    attach(pid)       — DebugActiveProcess on a running, user-started process,
                        then OpenProcess for a read/write handle. For targets
                        that need complex/manual startup. No free respawn (a
                        dead PID can't be re-attached).

Control is step-style so the driver stays explicit and debuggable:

    dbg = ManualDebugger()
    dbg.launch("target.exe")          # or dbg.attach(pid)
    dbg.wait_until_ready()            # pump past startup events
    # ... driver sends the payload via connection.py here ...
    sig = dbg.wait_for_crash()       # pump until the access violation
    if sig.crashed:
        handle = dbg.get_handle()
        # ... driver reads with read_memory(handle, addr, len) ...
    dbg.teardown()

Crash policy: FIRST-CHANCE access violation is treated as the crash (simplest;
see the note in wait_for_crash for switching to second-chance later).

WINDOWS ONLY. Cannot be exercised off-Windows. Validate in a VM: run the
win32.py struct self-check first, then test launch+crash against a real target.
"""

from __future__ import annotations
import ctypes

from . import win32 as w
from .signature import CrashSignature


def _quote(s: str) -> str:
    """
    Quote a command-line component if it contains spaces, so CreateProcessW's
    own parsing keeps it as one argument (paths with spaces are the usual case).
    Minimal on purpose — enough for exe paths and simple args like a script name.
    """
    if s and (" " in s or "\t" in s) and not (s.startswith('"') and s.endswith('"')):
        return '"' + s + '"'
    return s


class ManualDebugger:
    def __init__(self):
        self.pid = None
        self._handle = None          # OWNED process handle (read/write rights)
        self._thread_handle = None   # only set on launch (from PROCESS_INFORMATION)
        self._mode = None            # "launched" or "attached"
        self._alive = False

    # ------------------------------------------------------------------ entry

    def launch(self, exe_path: str, args: list[str] | None = None) -> int:
        """
        Launch `exe_path` under our debugger (DEBUG_ONLY_THIS_PROCESS) and own
        it from birth. Returns the new PID. The handle from CreateProcess is
        full-access, so it serves both read and write borrows.

        args: optional list of command-line arguments, e.g.
              launch(r"C:\\...\\python.exe", ["crashme.py"]). Each arg is quoted
              if it contains spaces so paths survive CreateProcess parsing.
        """
        si = w.STARTUPINFOW()
        si.cb = ctypes.sizeof(w.STARTUPINFOW)
        pi = w.PROCESS_INFORMATION()

        # Build the command line: argv[0] is the exe (quoted), then the args.
        # CreateProcessW parses lpCommandLine itself, so spaces must be quoted.
        parts = [_quote(exe_path)]
        if args:
            parts.extend(_quote(a) for a in args)
        cmdline = ctypes.create_unicode_buffer(" ".join(parts))

        ok = w.kernel32.CreateProcessW(
            exe_path,          # lpApplicationName
            cmdline,           # lpCommandLine (mutable, includes argv[0])
            None, None,        # process / thread security attrs
            False,             # inherit handles
            w.DEBUG_ONLY_THIS_PROCESS,
            None,              # environment (inherit)
            None,              # current dir (inherit)
            ctypes.byref(si),
            ctypes.byref(pi),
        )
        if not ok:
            raise OSError(
                f"CreateProcessW({exe_path!r}) failed (err={w.last_error()}). "
                "Bad path, or needs elevation?"
            )

        self.pid = pi.dwProcessId
        self._handle = pi.hProcess          # own this — full access from launch
        self._thread_handle = pi.hThread
        self._mode = "launched"
        self._alive = True
        return self.pid

    def attach(self, pid: int) -> int:
        """
        Attach as debugger to an already-running process, then open a read/write
        handle. For targets needing complex/manual startup. Returns the PID.
        """
        if not w.kernel32.DebugActiveProcess(pid):
            raise OSError(
                f"DebugActiveProcess(pid={pid}) failed (err={w.last_error()}). "
                "Correct PID? Matching privileges? Already being debugged?"
            )
        handle = w.kernel32.OpenProcess(w.PROCESS_RW_ALL, False, pid)
        if not handle:
            # back out of the debug relationship if we can't get a usable handle
            w.kernel32.DebugActiveProcessStop(pid)
            raise OSError(f"OpenProcess after attach failed (err={w.last_error()})")

        self.pid = pid
        self._handle = handle
        self._mode = "attached"
        self._alive = True
        return self.pid

    # ------------------------------------------------------------------ handle

    def get_handle(self):
        """
        Hand the OWNED process handle to a borrower (read_memory / write_memory).
        Guarded: raises if there's no handle yet. Borrowers must NOT close it —
        the debugger closes it once, at teardown.
        """
        if not self._handle:
            raise RuntimeError("no handle yet — call launch() or attach() first")
        return self._handle

    # ------------------------------------------------------------------ pump

    def wait_until_ready(self, timeout_ms: int = w.INFINITE) -> None:
        """
        Pump the initial burst of debug events (process/thread create, DLL
        loads, the loader breakpoint) and return once the target is running and
        ready to receive input. We stop pumping at the first breakpoint event —
        on both launch and attach Windows delivers an initial breakpoint once
        the process is initialized, which is our "ready" signal.
        """
        evt = w.DEBUG_EVENT()
        while True:
            if not w.kernel32.WaitForDebugEvent(ctypes.byref(evt), timeout_ms):
                raise OSError(
                    f"WaitForDebugEvent (startup) failed/timed out "
                    f"(err={w.last_error()})"
                )
            code = evt.dwDebugEventCode
            status = w.DBG_CONTINUE

            if code == w.EXCEPTION_DEBUG_EVENT:
                exc_code = evt.u.Exception.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
                if exc_code == w.EXCEPTION_BREAKPOINT:
                    # The initial loader breakpoint = process is initialized and
                    # ready. Continue past it and return control to the driver.
                    w.kernel32.ContinueDebugEvent(
                        evt.dwProcessId, evt.dwThreadId, w.DBG_CONTINUE
                    )
                    return
                # Any real exception before we're "ready" is unusual — let the
                # app handle it and keep pumping.
                status = w.DBG_EXCEPTION_NOT_HANDLED

            elif code == w.EXIT_PROCESS_DEBUG_EVENT:
                self._alive = False
                raise OSError("target exited during startup before becoming ready")

            # process/thread create, DLL load/unload, output-debug-string, etc.
            # are all just continued past.
            if not w.kernel32.ContinueDebugEvent(
                evt.dwProcessId, evt.dwThreadId, status
            ):
                raise OSError(f"ContinueDebugEvent (startup) failed (err={w.last_error()})")

    def wait_for_crash(self, timeout_ms: int = w.INFINITE) -> CrashSignature:
        """
        Pump events until the target faults or exits. Returns a CrashSignature.

        v1 policy: FIRST-CHANCE access violation is the crash. The moment we see
        an AV (or other fatal exception) we capture the fault address + code and
        return, leaving the target FROZEN at the fault so the driver can read
        memory before continuing/tearing down.

        To move to SECOND-CHANCE later: on a first-chance AV, return
        DBG_EXCEPTION_NOT_HANDLED via ContinueDebugEvent and keep pumping; the
        exception comes back a second time (dwFirstChance == 0) if unhandled —
        treat THAT as the crash. Second chance is more faithful to "this
        actually killed the process" but first chance is simpler and fine here.
        """
        evt = w.DEBUG_EVENT()
        FATAL = (
            w.EXCEPTION_ACCESS_VIOLATION,
            w.EXCEPTION_STACK_OVERFLOW,
            w.EXCEPTION_ILLEGAL_INSTRUCTION,
            w.EXCEPTION_GUARD_PAGE,
        )
        while True:
            if not w.kernel32.WaitForDebugEvent(ctypes.byref(evt), timeout_ms):
                raise OSError(
                    f"WaitForDebugEvent (crash wait) failed/timed out "
                    f"(err={w.last_error()})"
                )
            code = evt.dwDebugEventCode
            status = w.DBG_CONTINUE

            if code == w.EXCEPTION_DEBUG_EVENT:
                rec = evt.u.Exception.ExceptionRecord
                exc_code = rec.ExceptionCode & 0xFFFFFFFF

                if exc_code == w.EXCEPTION_BREAKPOINT and evt.u.Exception.dwFirstChance:
                    # stray breakpoint (e.g. int3) — continue past it
                    status = w.DBG_CONTINUE
                elif exc_code in FATAL:
                    # THE CRASH. Leave the target frozen (do NOT ContinueDebugEvent
                    # here) so the driver can read memory at the fault.
                    return CrashSignature(
                        crashed=True,
                        fault_address=rec.ExceptionAddress or 0,
                        exception_code=exc_code,
                        controlled_ip=None,   # needs thread CONTEXT — later
                    )
                else:
                    # some other first-chance exception: let the app try to
                    # handle it, keep pumping
                    status = w.DBG_EXCEPTION_NOT_HANDLED

            elif code == w.EXIT_PROCESS_DEBUG_EVENT:
                # Exited without the crash we expected — real signal: a bad byte
                # may have prevented the crash entirely.
                self._alive = False
                return CrashSignature(crashed=False)

            if not w.kernel32.ContinueDebugEvent(
                evt.dwProcessId, evt.dwThreadId, status
            ):
                raise OSError(f"ContinueDebugEvent (crash wait) failed (err={w.last_error()})")

    # ------------------------------------------------------------------ teardown

    def teardown(self) -> None:
        """
        Mode-aware cleanup and the ONE place the owned handle is closed.
          launched  -> terminate the process (it's ours to kill).
          attached  -> detach and LEAVE the user's process running.
        Safe to call more than once.
        """
        if self._mode == "launched" and self._handle and self._alive:
            w.kernel32.TerminateProcess(self._handle, 0)
        if self._mode == "attached" and self.pid is not None:
            w.kernel32.DebugActiveProcessStop(self.pid)

        if self._thread_handle:
            w.kernel32.CloseHandle(self._thread_handle)
            self._thread_handle = None
        if self._handle:
            w.kernel32.CloseHandle(self._handle)   # the one close
            self._handle = None
        self._alive = False
        self._mode = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.teardown()


if __name__ == "__main__":
    # Smoke test for the debugger, in two levels.
    #
    # Level 1 (any exe, even notepad) — proves launch + startup pump + handle:
    #   python -m badcharhunter.manual_debugger notepad.exe
    #
    # Level 1 via attach to a running process:
    #   python -m badcharhunter.manual_debugger --attach <pid>
    #
    # Level 2 (needs a target that actually crashes on startup/soon after) —
    # also waits for and prints the crash signature:
    #   python -m badcharhunter.manual_debugger vuln.exe --expect-crash
    #
    # Note: Level 2 here only makes sense for a target that crashes on its own
    # shortly after launch, since this smoke test does not send a payload
    # (sending is the driver's job). For the real send-then-crash flow, use the
    # driver, not this.
    import sys

    argv = sys.argv[1:]
    if not argv:
        print("usage:")
        print("  manual_debugger <exe_path> [exe_args...] [--expect-crash]")
        print("  manual_debugger --attach <pid> [--expect-crash]")
        raise SystemExit(1)

    expect_crash = "--expect-crash" in argv
    argv = [a for a in argv if a != "--expect-crash"]   # strip our flag

    dbg = ManualDebugger()

    try:
        if argv[0] == "--attach":
            if len(argv) < 2:
                print("usage: manual_debugger --attach <pid> [--expect-crash]")
                raise SystemExit(1)
            pid = int(argv[1])
            print(f"[*] attaching to pid {pid} ...")
            dbg.attach(pid)
            print(f"[+] attached. pid={dbg.pid} handle={dbg.get_handle()}")
            print("[*] pumping until ready ...")
            dbg.wait_until_ready()
            print("[+] target reported ready (initial breakpoint reached)")

        else:
            exe = argv[0]
            exe_args = argv[1:]   # anything after the exe path = target's args
            print(f"[*] launching {exe!r} args={exe_args} under debugger ...")
            dbg.launch(exe, exe_args or None)
            print(f"[+] launched. pid={dbg.pid} handle={dbg.get_handle()}")
            print("[*] pumping until ready ...")
            dbg.wait_until_ready()
            print("[+] target reported ready (initial breakpoint reached)")

        if expect_crash:
            print("[*] waiting for crash ...")
            sig = dbg.wait_for_crash()
            print(f"[+] crash signature: {sig.describe()}")
            if sig.crashed:
                print(f"    fault @ 0x{sig.fault_address:x} "
                      f"code 0x{sig.exception_code:08x}")

        print("[*] tearing down ...")
    finally:
        dbg.teardown()
        print("[+] clean.")