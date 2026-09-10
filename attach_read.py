from __future__ import annotations
import ctypes
 
from . import win32 as w
 
 
def read_memory(handle, address: int, length: int) -> bytes:
    """
    Read `length` bytes at `address` from a process, using a handle you already
    hold (typically the debugger's, via get_handle()).
 
    BORROWS the handle: does not open it, does not close it. The handle's owner
    is responsible for its lifecycle — never CloseHandle() a handle passed here.
    """
    buf = (ctypes.c_char * length)()
    nread = ctypes.c_size_t(0)
    ok = w.kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(address), buf, length, ctypes.byref(nread)
    )
    if not ok:
        raise OSError(
            f"ReadProcessMemory @ 0x{address:x} (len={length}) failed "
            f"(err={w.last_error()}). Address unmapped, or no access."
        )
    return bytes(buf[: nread.value])
 
 
class OpenReader:
    """
    Read memory via OpenProcess + ReadProcessMemory WITHOUT debugging the target.
 
    For the WinDbg-alongside mode (your tool is not the debugger) and for
    isolated smoke-testing that plain reads work. Opens and closes its OWN
    handle; the actual read is delegated to read_memory().
    """
 
    def __init__(self, pid: int):
        self.pid = pid
        self._handle = None
 
    def open(self) -> None:
        self._handle = w.kernel32.OpenProcess(
            w.PROCESS_VM_READ | w.PROCESS_QUERY_INFORMATION, False, self.pid
        )
        if not self._handle:
            raise OSError(
                f"OpenProcess(pid={self.pid}) failed (err={w.last_error()}). "
                "Are you running elevated? Is the PID correct?"
            )
 
    def read(self, address: int, length: int) -> bytes:
        if not self._handle:
            raise RuntimeError("call open() first (or use as a context manager)")
        return read_memory(self._handle, address, length)
 
    def close(self) -> None:
        if self._handle:
            w.kernel32.CloseHandle(self._handle)
            self._handle = None
 
    def __enter__(self):
        self.open()
        return self
 
    def __exit__(self, *exc):
        self.close()
 
 
def hexdump(data: bytes, base: int = 0) -> str:
    """
    Small hexdump for eyeballing what you read. Convenience, not core.
 
    base: the absolute address the first byte corresponds to, used only to label
    the left column so displayed addresses match real memory. Does not skip or
    offset any data — all bytes passed in are shown.
    """
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:08x}  {hexpart:<47}  {asciipart}")
    return "\n".join(lines)
 
 
if __name__ == "__main__":
    # Smoke test (WinDbg-alongside / standalone read, no debugging):
    #   python -m badcharhunter.attach_read <pid> <hex_address> <length>
    # Uses OpenReader, which opens its own read handle. In the full tool the
    # debugger owns the handle and you call read_memory(get_handle(), ...)
    # instead — this CLI is just for isolated read testing.
    import sys
 
    if len(sys.argv) < 4:
        print("usage: attach_read <pid> <hex_address> <length>")
        raise SystemExit(1)
 
    pid = int(sys.argv[1])
    address = int(sys.argv[2], 16)
    length = int(sys.argv[3])
 
    print(f"[*] OpenReader: pid={pid} @ 0x{address:x} len={length}")
    with OpenReader(pid) as r:
        data = r.read(address, length)
    print(f"[+] read {len(data)} bytes:")
    print(hexdump(data, base=address))
 