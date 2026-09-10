from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional
 
 
@dataclass(frozen=True)
class CrashSignature:
    """
    A comparable fingerprint of a crash. Fields are optional so the debugger
    layer can fill in whatever it can observe on a given target.
 
    crashed         — did the target fault at all?
    fault_address   — instruction pointer at the fault (EIP/RIP), if known.
    exception_code  — e.g. 0xC0000005 (access violation), if known.
    controlled_ip   — did our bytes control the instruction pointer?
    """
    crashed: bool
    fault_address: Optional[int] = None
    exception_code: Optional[int] = None
    controlled_ip: Optional[bool] = None
 
    def matches(self, other: "CrashSignature", *, strict: bool = False) -> bool:
        """
        Does `other` look like the same crash as `self` (the baseline)?
 
        Non-strict (default): compare only fields both signatures have set.
        This tolerates targets where we can't observe every field. strict=True
        requires every field present in the baseline to match exactly.
        """
        if self.crashed != other.crashed:
            return False
        for attr in ("fault_address", "exception_code", "controlled_ip"):
            a = getattr(self, attr)
            b = getattr(other, attr)
            if strict:
                if a != b:
                    return False
            else:
                if a is not None and b is not None and a != b:
                    return False
        return True
 
    def describe(self) -> str:
        if not self.crashed:
            return "no crash"
        parts = []
        if self.fault_address is not None:
            parts.append(f"ip=0x{self.fault_address:08x}")
        if self.exception_code is not None:
            parts.append(f"exc=0x{self.exception_code:08x}")
        if self.controlled_ip is not None:
            parts.append(f"controlled={'yes' if self.controlled_ip else 'no'}")
        return "crash(" + ", ".join(parts) + ")" if parts else "crash(unspecified)"
 
 
# A "probe" runs one group of bytes end-to-end (restart target, send, observe)
# and returns the resulting CrashSignature. The debugger layer supplies this;
# the search below only calls it. Signature: probe(group: bytes) -> CrashSignature
Probe = Callable[[bytes], CrashSignature]
 
 
def bisect_bad_bytes(
    candidates: list[int],
    baseline: CrashSignature,
    probe: Probe,
    *,
    strict: bool = False,
) -> list[int]:
    """
    Divide-and-conquer search for bad bytes using the crash-signature oracle.
 
    Sends `candidates` as one group; if the crash matches baseline, the whole
    group is clean. Otherwise split and recurse into each half, isolating the
    offending byte(s). Handles multiple bad bytes because we recurse into BOTH
    halves whenever a group is dirty.
 
    Returns the sorted list of bad byte values found.
 
    Cost: ~O(k log n) probes for k bad bytes in n candidates — each probe is a
    full restart-and-retrigger, so this is the expensive path. Prefer the linear
    memory diff first; fall back here when the crash signal itself is unstable.
    """
    bad: set[int] = set()
    _bisect(candidates, baseline, probe, strict, bad)
    return sorted(bad)
 
 
def _bisect(
    group: list[int],
    baseline: CrashSignature,
    probe: Probe,
    strict: bool,
    bad: set[int],
) -> None:
    if not group:
        return
    sig = probe(bytes(group))
    if baseline.matches(sig, strict=strict):
        return  # whole group clean
    if len(group) == 1:
        bad.add(group[0])   # isolated a bad byte
        return
    mid = len(group) // 2
    _bisect(group[:mid], baseline, probe, strict, bad)
    _bisect(group[mid:], baseline, probe, strict, bad)
 