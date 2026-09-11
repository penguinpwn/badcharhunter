from __future__ import annotations
import ctypes
 
from . import win32 as w
from .attach_read import read_memory
 
 
def iter_readable_regions(handle):
    """
    Yield (base, size) for each committed, readable, non-guard region in the
    target, using VirtualQueryEx to walk the address space from 0 upward.
    """
    address = 0
    mbi = w.MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)
 
    while True:
        written = w.kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size
        )
        if not written:
            break  # past the end of the address space (or query failed)
 
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if size == 0:
            break  # no progress possible; avoid an infinite loop
 
        if w.is_readable_region(mbi.State, mbi.Protect):
            yield base, size
 
        address = base + size  # advance to the next region
 
 
def find_pattern(handle, pattern: bytes, *, max_hits: int | None = None) -> list[int]:
    """
    Search all committed, readable, non-guard regions for `pattern`. Return a
    list of every address where it occurs (empty if none). Borrows `handle`.
 
    max_hits: stop after this many matches if set (e.g. 1 when you only want the
    first). None = find them all.
    """
    if not pattern:
        raise ValueError("pattern must be non-empty")
 
    hits: list[int] = []
    for base, size in iter_readable_regions(handle):
        try:
            blob = read_memory(handle, base, size)
        except OSError:
            # A region can become unreadable between the query and the read
            # (races, odd protections). Skip it rather than aborting the search.
            continue
 
        start = 0
        while True:
            idx = blob.find(pattern, start)
            if idx == -1:
                break
            hits.append(base + idx)
            if max_hits is not None and len(hits) >= max_hits:
                return hits
            start = idx + 1  # allow overlapping / repeated matches
 
    return hits
 
 
def find_after(handle, marker: bytes, *, max_hits: int | None = None) -> list[int]:
    """
    Like find_pattern, but return the address immediately AFTER each marker
    match — i.e. where the buffer begins when the marker is placed right before
    it. One entry per marker hit.
    """
    return [addr + len(marker) for addr in find_pattern(handle, marker, max_hits=max_hits)]
 
 
if __name__ == "__main__":
    # Smoke test: search a running process for a pattern.
    #   python -m badcharhunter.mem_search <pid> <hex_pattern>
    # e.g. python -m badcharhunter.mem_search 1234 424348   (searches for "BCH")
    # Opens its own handle (like OpenReader) just for this standalone test; the
    # real tool passes the debugger's handle to find_pattern directly.
    import sys
    from .attach_read import OpenReader
 
    if len(sys.argv) < 3:
        print("usage: mem_search <pid> <hex_pattern>")
        print("  e.g. mem_search 1234 424348   (hex for 'BCH')")
        raise SystemExit(1)
 
    pid = int(sys.argv[1])
    pattern = bytes.fromhex(sys.argv[2])
 
    print(f"[*] searching pid {pid} for {pattern!r} ({pattern.hex()}) ...")
    with OpenReader(pid) as r:
        hits = find_pattern(r._handle, pattern)
    if hits:
        print(f"[+] {len(hits)} match(es):")
        for h in hits:
            print(f"    0x{h:x}")
    else:
        print("[-] pattern not found in any readable region.")
 