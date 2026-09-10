"""
byteset.py — generation of candidate byte sets for bad-char hunting.

The core idea: build a sequence of all candidate bytes we want to test
(default \\x01-\\xff), minus any the operator already knows are bad or
wants to exclude for the input vector. As bad chars are confirmed, they
get removed and the set is regenerated for the next round.

No debugger, no network — pure logic, fully unit-testable.
"""

from __future__ import annotations
from dataclasses import dataclass, field


# Bytes that are bad in a huge fraction of vectors. \x00 (null terminator),
# \x0a (newline), \x0d (carriage return). We exclude \x00 by default because
# it terminates C strings almost everywhere; the operator opts the others
# in/out per target.
COMMON_BAD = {0x00}
COMMON_SUSPECT = {0x0a, 0x0d}


@dataclass
class ByteSet:
    """A candidate set of bytes to send, tracking what's excluded and why."""

    # Bytes confirmed bad this session (removed from every future payload).
    confirmed_bad: set[int] = field(default_factory=set)
    # Bytes the operator pre-excluded (known bad for this vector, e.g. \x00).
    excluded: set[int] = field(default_factory=lambda: set(COMMON_BAD))
    # Full candidate range. Default skips \x00 by starting at 0x01.
    start: int = 0x01
    end: int = 0xFF  # inclusive

    def exclude(self, *bytes_: int) -> None:
        """Operator pre-excludes bytes known-bad for this input vector."""
        for b in bytes_:
            _check_range(b)
            self.excluded.add(b)

    def mark_bad(self, *bytes_: int) -> None:
        """Confirm bytes as bad; they drop out of all future payloads."""
        for b in bytes_:
            _check_range(b)
            self.confirmed_bad.add(b)

    def candidates(self) -> list[int]:
        """The bytes to actually send this round, in ascending order."""
        removed = self.excluded | self.confirmed_bad
        return [b for b in range(self.start, self.end + 1) if b not in removed]

    def payload(self) -> bytes:
        """The candidate bytes as a raw payload buffer."""
        return bytes(self.candidates())

    def as_hex(self) -> str:
        r"""Human-readable \xNN string for logging / blog screenshots."""
        return "".join(f"\\x{b:02x}" for b in self.candidates())

    def remaining(self) -> int:
        return len(self.candidates())

    def summary(self) -> str:
        return (
            f"ByteSet: {self.remaining()} candidates | "
            f"excluded={_fmt(self.excluded)} | "
            f"confirmed_bad={_fmt(self.confirmed_bad)}"
        )


def _check_range(b: int) -> None:
    if not 0x00 <= b <= 0xFF:
        raise ValueError(f"byte out of range: {b!r} (must be 0x00-0xff)")


def _fmt(bytes_: set[int]) -> str:
    if not bytes_:
        return "{}"
    return "{" + ",".join(f"0x{b:02x}" for b in sorted(bytes_)) + "}"