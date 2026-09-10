"""
compare.py — diff a sent byte set against what actually landed in memory.

Two strategies:

  linear_diff  — walk both buffers in lockstep, report the first divergence.
                 Cheap and correct when the buffer lands intact-until-corrupted
                 (a bad char mangles the tail but earlier bytes align 1:1).

  lcs_diff     — Longest Common Subsequence alignment. Robust when the landed
                 buffer is shifted, has bytes inserted/removed, or is otherwise
                 corrupted such that lockstep comparison desyncs. This is the
                 same class of approach Corelan's mona.py uses for exactly this
                 reason: naive index-by-index comparison falls apart the moment
                 the buffers differ in *length*, not just content.

Both report suspect bytes. Because a bad char can corrupt the byte *after* it
(or make the true break point ambiguous), the first divergence flags BOTH the
diverging byte and its successor as suspect — the operator confirms which.

Pure logic, no debugger. Feed it two `bytes` objects.
"""

from __future__ import annotations
from dataclasses import dataclass


@dataclass
class DiffResult:
    aligned_len: int          # how many bytes matched cleanly before divergence
    first_divergence: int | None   # index into the SENT buffer, or None if clean
    suspects: list[int]       # byte VALUES flagged as possibly-bad (from sent)
    clean: bool               # True if buffers matched fully

    def report(self) -> str:
        if self.clean:
            return f"CLEAN — all {self.aligned_len} bytes landed intact."
        sus = ",".join(f"0x{b:02x}" for b in self.suspects) or "(none)"
        return (
            f"DIVERGENCE at sent index {self.first_divergence} "
            f"({self.aligned_len} bytes clean before it). "
            f"Suspect byte(s): {sus}"
        )


def linear_diff(sent: bytes, landed: bytes) -> DiffResult:
    """
    Lockstep comparison. Good when nothing shifted — only the tail got mangled.

    On the first mismatch we flag the sent byte at that position AND the next
    sent byte, because bad chars frequently damage their successor or make the
    exact boundary ambiguous. The operator removes the confirmed one and re-runs.
    """
    n = min(len(sent), len(landed))
    for i in range(n):
        if sent[i] != landed[i]:
            suspects = [sent[i]]
            if i + 1 < len(sent):
                suspects.append(sent[i + 1])
            return DiffResult(
                aligned_len=i,
                first_divergence=i,
                suspects=suspects,
                clean=False,
            )
    # No mismatch within the overlap. If landed is shorter, the buffer was
    # truncated — the byte at the truncation point in `sent` is suspect.
    if len(landed) < len(sent):
        i = len(landed)
        suspects = [sent[i]] if i < len(sent) else []
        if i + 1 < len(sent):
            suspects.append(sent[i + 1])
        return DiffResult(
            aligned_len=i,
            first_divergence=i,
            suspects=suspects,
            clean=False,
        )
    return DiffResult(aligned_len=n, first_divergence=None, suspects=[], clean=True)


def lcs_diff(sent: bytes, landed: bytes) -> DiffResult:
    """
    LCS-based alignment for shifted / insertion-corrupted buffers.

    Computes the longest common subsequence, then finds the first position in
    `sent` that is NOT part of the common subsequence — that's where the landed
    buffer first failed to reproduce a sent byte. Handles the case where the
    landed buffer has junk inserted or bytes dropped, which desyncs linear_diff.

    Note: O(n*m) time/space. For a 255-byte set this is trivial; if you ever
    diff huge shellcode buffers, chunk it or cap with `first_bytes`.
    """
    la, lb = len(sent), len(landed)
    # DP table of LCS lengths.
    dp = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la - 1, -1, -1):
        for j in range(lb - 1, -1, -1):
            if sent[i] == landed[j]:
                dp[i][j] = dp[i + 1][j + 1] + 1
            else:
                dp[i][j] = max(dp[i + 1][j], dp[i][j + 1])

    # Walk the alignment; find first sent-byte that isn't matched in sequence.
    i = j = 0
    aligned = 0
    while i < la and j < lb:
        if sent[i] == landed[j]:
            i += 1
            j += 1
            aligned += 1
        elif dp[i + 1][j] >= dp[i][j + 1]:
            # sent[i] dropped from landed — this byte is the suspect.
            suspects = [sent[i]]
            if i + 1 < la:
                suspects.append(sent[i + 1])
            return DiffResult(
                aligned_len=aligned,
                first_divergence=i,
                suspects=suspects,
                clean=False,
            )
        else:
            j += 1  # junk inserted in landed; skip it, keep aligning
    if i < la:
        # Ran off the end of landed while sent bytes remain — truncated.
        suspects = [sent[i]]
        if i + 1 < la:
            suspects.append(sent[i + 1])
        return DiffResult(
            aligned_len=aligned,
            first_divergence=i,
            suspects=suspects,
            clean=False,
        )
    return DiffResult(aligned_len=aligned, first_divergence=None, suspects=[], clean=True)