from __future__ import annotations
from dataclasses import dataclass, field

from .config import HuntConfig
from .connection import Connection
from .manual_debugger import ManualDebugger
from .mem_search import find_after
from .attach_read import read_memory, hexdump


@dataclass
class RoundResult:
    crashed: bool
    fault_address: int | None
    exception_code: int | None
    landed: bytes | None          # bytes read back at the FIRST marker match
    buffer_addrs: list[int]       # every marker match (address just past marker)
    landed_all: list[bytes] = field(default_factory=list)  # bytes at each match
    reg_value: int | None = None          # value of the landing register at crash
    reg_window: bytes = b""               # memory read around the register (pointer mode)
    note: str = ""

    def summary(self) -> str:
        if not self.crashed:
            return f"no crash{(' — ' + self.note) if self.note else ''}"
        s = f"crash @ 0x{self.fault_address:x} code 0x{self.exception_code:08x}"
        if self.buffer_addrs:
            s += f" | buffer found at {len(self.buffer_addrs)} spot(s)"
        else:
            s += " | buffer NOT found in memory"
        return s


def build_payload(cfg: HuntConfig, test_bytes: bytes) -> bytes:
    """
    Assemble the buffer that goes in the {{BUF}} slot:
        [marker][test bytes][padding of known_good up to crash_size]
    Fixed total length (crash_size) every round so only the test bytes vary.
    """
    core = cfg.marker + test_bytes
    if len(core) > cfg.crash_size:
        raise ValueError(
            f"marker+test_bytes ({len(core)}) exceeds crash_size ({cfg.crash_size})"
        )
    pad = bytes([cfg.known_good]) * (cfg.crash_size - len(core))
    return core + pad


class DebugSession:
    """
    Manages the debugger ACROSS rounds so a target that survives a no-crash
    payload can be reused without a restart+re-attach every time.

    Rule:
      - After a CRASH, the process is dead -> next round must restart target and
        re-attach to a new PID (prompt the operator).
      - After a NO-CRASH, the process is still alive -> reuse the same attached
        session, no prompt, no restart. (Optionally force a restart if you
        suspect the process got wedged.)

    This roughly halves the manual restarts, since bisection produces many
    no-crash rounds in a row against the same surviving process.
    """

    def __init__(self, cfg: HuntConfig, prompt=input):
        self.cfg = cfg
        self.prompt = prompt
        self._dbg: ManualDebugger | None = None
        self._alive = False   # is the currently-attached target still usable?

    def ensure_target(self) -> ManualDebugger:
        """
        Return a debugger attached to a live, ready target. Reuses the current
        one if it survived the last round; otherwise gets a fresh one:
          - respawn recipe set: run it (restart target, resolve PID, attach) — no prompt
          - otherwise: prompt for a new PID and attach
        (Launch mode — the tool self-launching the exe — is not in this version;
        it needs a concurrent background debug pump to work for servers. Attach
        mode + respawn recipes cover exes, services, and servers today.)
        """
        if self._dbg is not None and self._alive:
            return self._dbg   # reuse the surviving process, no prompt, no recipe

        # need a fresh target
        self._teardown_current()
        dbg = ManualDebugger()

        if self.cfg.respawn_recipe:
            # Automated respawn: run the recipe (restart service, resolve PID),
            # then attach to the PID it produces. No prompt. Runs only here —
            # i.e. only when a fresh target is needed (after a crash), never on
            # a no-crash reuse.
            from .recipe import run_recipe
            print("[*] running respawn recipe to bring the target back ...")
            pid = run_recipe(self.cfg.respawn_recipe)
            dbg.attach(pid)
            dbg.wait_until_ready()
            self._dbg = dbg
            self._alive = True
            self._wait_until_listening()
        else:  # attach mode, manual
            raw = self.prompt("[?] Restart the target, then enter its new PID: ").strip()
            pid = int(raw)
            dbg.attach(pid)
            dbg.wait_until_ready()
            self._dbg = dbg
            self._alive = True
            self._wait_until_listening()
        return dbg

    def _wait_until_listening(self, attempts: int = 20, delay: float = 0.25) -> None:
        """
        Poll the target's port until a TCP connection succeeds, so we don't send
        before a freshly launched server has bound its socket. Best-effort: if it
        never comes up, we return anyway and the round's send will surface the
        real error.
        """
        import socket as _socket
        import time as _time
        for _ in range(attempts):
            try:
                with _socket.create_connection((self.cfg.host, self.cfg.port),
                                               timeout=0.5):
                    return  # port is open
            except OSError:
                _time.sleep(delay)
        # fall through — let the actual send report the problem if still down

    def mark_crashed(self) -> None:
        """The target crashed (is now dead); force a fresh attach next round."""
        self._alive = False
        self._teardown_current()

    def mark_survived(self) -> None:
        """The target did not crash; it stays alive and reusable next round."""
        self._alive = True

    def force_restart(self) -> None:
        """Drop the current target even if alive (use if it seems wedged)."""
        self._alive = False
        self._teardown_current()

    def _teardown_current(self) -> None:
        if self._dbg is not None:
            try:
                self._dbg.teardown()
            except Exception:
                pass
            self._dbg = None

    def close(self) -> None:
        self._teardown_current()

    def current_debugger(self):
        """The live debugger — for reading the crashed target's registers."""
        if self._dbg is None:
            raise RuntimeError("no active debugger")
        return self._dbg


def run_one_round(cfg: HuntConfig, test_bytes: bytes, session: "DebugSession",
                  *, crash_timeout_ms: int = 3000) -> RoundResult:
    """
    Run ONE round, reusing the session's target when possible.
      1. ensure a live, ready target (reuse if it survived; else prompt+attach)
      2. send [marker][test_bytes][padding] as the HTTP request
      3. wait for crash (bounded by crash_timeout_ms)
      4. crashed -> locate buffer via marker, read ALL matches; mark target dead
         no crash -> mark target survived (reusable next round)
    """
    payload = build_payload(cfg, test_bytes)

    dbg = session.ensure_target()          # reuse or fresh attach
    landed = None
    landed_all: list[bytes] = []
    buffer_addrs: list[int] = []
    note = ""

    # Deliver the payload: a custom sender_fn (binary/custom protocols) if set,
    # otherwise the text-template Connection.
    if cfg.sender_fn is not None:
        cfg.sender_fn(payload, cfg.host, cfg.port)
    else:
        conn = Connection(host=cfg.host, port=cfg.port, template=cfg.template,
                          timeout=cfg.timeout, recv_after=cfg.recv_after)
        conn.send(payload)

    try:
        sig = dbg.wait_for_crash(timeout_ms=crash_timeout_ms)
    except OSError:
        # timed out: no crash. Target still alive -> reusable next round.
        session.mark_survived()
        return RoundResult(
            crashed=False, fault_address=None, exception_code=None,
            landed=None, buffer_addrs=[],
            note=f"no crash within {crash_timeout_ms} ms",
        )

    if sig.crashed:
        handle = dbg.get_handle()
        buffer_addrs = find_after(handle, cfg.marker)
        for addr in buffer_addrs:
            try:
                landed_all.append(read_memory(handle, addr, len(test_bytes)))
            except OSError:
                landed_all.append(b"")
        landed = landed_all[0] if landed_all else None
        if not buffer_addrs:
            note = "crash but marker not found in memory"

        # Capture register data NOW, while the target is still frozen at the
        # crash and the debugger is alive — because mark_crashed() below tears
        # the debugger down. The register oracle then works on this stored data,
        # not on a live debugger.
        reg_value = None
        reg_window = b""
        if cfg.landing_register:
            try:
                from .regs import read_register
                tid = dbg.get_fault_thread_handle()
                reg_value = read_register(tid, cfg.landing_register)
                if cfg.register_mode == "pointer" and reg_value is not None:
                    window_back = 1024
                    window_fwd = max(4096, cfg.crash_size)
                    start = reg_value - window_back
                    if start < 0:
                        start = 0
                    try:
                        reg_window = read_memory(handle, start, window_back + window_fwd)
                    except OSError:
                        reg_window = b""
            except Exception:
                reg_value = None

        session.mark_crashed()             # dead -> fresh attach next round
        return RoundResult(
            crashed=True,
            fault_address=sig.fault_address,
            exception_code=sig.exception_code,
            landed=landed, buffer_addrs=buffer_addrs, landed_all=landed_all,
            reg_value=reg_value, reg_window=reg_window,
            note=note,
        )
    else:
        # process exited without our crash — treat as dead / no-crash
        session.mark_survived()
        return RoundResult(
            crashed=False, fault_address=None, exception_code=None,
            landed=None, buffer_addrs=[],
            note="target exited without the expected crash",
        )


def _diff_landed(cfg: HuntConfig, sent: bytes, result: RoundResult):
    """
    Compare the sent bytes against EACH marker match and return the diff for
    every match, so the operator can see which spot is the true buffer.
    Returns a list of (address, DiffResult).
    """
    from .compare import lcs_diff
    diffs = []
    for addr, landed in zip(result.buffer_addrs, result.landed_all):
        diffs.append((addr, lcs_diff(sent, landed)))
    return diffs


def hunt(cfg: HuntConfig, *, prompt=input, crash_timeout_ms: int = 3000) -> list[int]:
    """
    The full hunt. Returns the list of confirmed bad-char byte VALUES found
    (beyond the pre-excluded ones).

    Flow:
      0. Baseline — send known_good x crash_size (no candidates), confirm it
         crashes. If the baseline doesn't crash, the whole premise is wrong
         (bad crash_size / field / not vulnerable), so stop and say so.
      1. Send the full candidate set:
           crashes  -> diff sent vs landed -> sent bytes that didn't survive
                       are bad chars.
           no crash -> a bad byte prevented the crash -> bisect to isolate it.
      2. Mark found bad bytes, regenerate the set, resend. Repeat until the set
         lands clean (crashes with every sent byte intact).
      3. Report all bad chars found.

    A bad char is always a byte that WAS SENT and did NOT come back intact.
    Pre-excluded bytes are never sent and never reported.
    """
    from .byteset import ByteSet

    print(cfg.show())
    print()

    # ---- byte set, seeded with the config's exclusions ----
    bs = ByteSet()
    for b in sorted(cfg.excluded):
        bs.exclude(b)

    session = DebugSession(cfg, prompt=prompt)
    try:
        return _hunt_with_session(cfg, bs, session, prompt, crash_timeout_ms)
    finally:
        session.close()


def _hunt_with_session(cfg, bs, session, prompt, crash_timeout_ms) -> list[int]:
    # ---- 0. baseline (retry-able: a flaky first attempt shouldn't kill the hunt) ----
    print("[*] Baseline: sending known_good x crash_size (no candidates) ...")
    while True:
        baseline = run_one_round(cfg, b"", session,
                                 crash_timeout_ms=crash_timeout_ms)
        if baseline.crashed:
            print(f"[+] Baseline crash confirmed: {baseline.summary()}\n")
            break
        print(f"[!] Baseline did NOT crash ({baseline.summary()}).")
        print("    Possible causes: wrong PID entered, target not fully restarted,")
        print("    wrong crash_size/field/template, target not vulnerable as expected,")
        print("    or your known_good byte is itself a bad char.")
        ans = prompt("    Retry baseline? [y/N]: ").strip().lower()
        if ans != "y":
            print("[!] Giving up on baseline. Fix the setup and re-run.")
            return []

    found_bad: list[int] = []

    # ---- 1-2. iterate: send full set, diff or bisect, reduce, repeat ----
    round_no = 0
    while True:
        round_no += 1
        cands = bs.payload()
        print(f"[*] Round {round_no}: sending {len(cands)} candidate bytes "
              f"(confirmed bad so far: {[hex(b) for b in found_bad]})")

        result = run_one_round(cfg, cands, session,
                               crash_timeout_ms=crash_timeout_ms)
        print(f"    {result.summary()}")

        if result.crashed:
            # signature_detection = go straight to register-based detection,
            # skipping the memory-diff / buffer-finding entirely.
            if cfg.signature_detection:
                print(f"[*] signature_detection on — using "
                      f"{cfg.landing_register.upper()} ({cfg.register_mode}).")
                done = _run_register_detection(
                    cfg, session, cands, result, found_bad, bs, crash_timeout_ms)
                if done:
                    break
                continue

            diffs = _diff_landed(cfg, cands, result)

            # Buffer not found in memory: memory-diff can't work. Fall back to
            # register-based detection if a landing_register is set; otherwise
            # tell the operator to enable it.
            if not diffs:
                if not cfg.landing_register:
                    print("[!] Crashed, but the buffer was NOT found in memory. "
                          "This target likely overwrites a register directly "
                          "(e.g. EIP). Set a landing_register and re-run, e.g.:")
                    print("      set landing_register esp")
                    print("      set register_mode pointer   (or: direct)")
                    print("    then the tool will use signature/register-based "
                          "detection. (Or 'set signature_detection true' to use "
                          "it from the start.)")
                    break
                print(f"[*] Buffer not found in memory — switching to "
                      f"register-based detection on "
                      f"{cfg.landing_register.upper()} ({cfg.register_mode}).")
                done = _run_register_detection(
                    cfg, session, cands, result, found_bad, bs, crash_timeout_ms)
                if done:
                    break
                continue

            # Default: auto-pick the most-aligned copy (most likely the real
            # buffer). Show all so the operator can see them.
            best_addr, best = max(diffs, key=lambda d: d[1].aligned_len)
            for idx, (addr, d) in enumerate(diffs):
                tag = " <- best" if addr == best_addr else ""
                print(f"      [{idx}] @0x{addr:x}: {d.report()}{tag}")

            # Manual override: when there's more than one match and the operator
            # asked to choose, let them pick which address is the real buffer.
            if cfg.manual_buffer_select and len(diffs) > 1:
                raw = prompt(f"    Pick buffer index to use [0-{len(diffs)-1}] "
                             f"(Enter = keep auto '{hex(best_addr)}'): ").strip()
                if raw != "":
                    try:
                        choice = int(raw)
                        if 0 <= choice < len(diffs):
                            best_addr, best = diffs[choice]
                            print(f"    -> using @0x{best_addr:x} (manual)")
                        else:
                            print("    -> out of range; keeping auto pick.")
                    except ValueError:
                        print("    -> not a number; keeping auto pick.")

            if best.clean:
                print("[+] All sent bytes landed intact. Hunt complete.")
                break

            # best.suspects is [prime] or [prime, neighbor]. The PRIME suspect
            # (the byte at the divergence) is the confirmed bad char. The N+1
            # neighbor is only POSSIBLY affected — we do NOT commit it. If it is
            # truly bad, the next round (with prime removed) will diverge at it
            # and flag it as its own prime. This keeps found_bad = confirmed only.
            if not best.suspects:
                print("[!] Divergence but no suspect byte reported; stopping.")
                break
            prime = best.suspects[0]
            neighbor = best.suspects[1] if len(best.suspects) > 1 else None

            if prime in found_bad:
                print("[!] Prime suspect already known but still diverging; stopping.")
                break

            found_bad.append(prime)
            bs.mark_bad(prime)
            msg = f"    -> confirmed bad char: {hex(prime)}"
            if neighbor is not None:
                msg += f" (neighbor {hex(neighbor)} possibly affected — will verify next round)"
            print(msg + "; removing and resending.\n")

        else:
            print("    -> no crash; bisecting to isolate the offending byte(s).")
            bad = _bisect_no_crash(cfg, cands, session, crash_timeout_ms)
            if not bad:
                print("[!] Bisection found no offending byte (unexpected); stopping.")
                break
            for b in bad:
                if b not in found_bad:
                    found_bad.append(b)
                    bs.mark_bad(b)
            print(f"    -> bisection found bad char(s): {[hex(b) for b in bad]}; "
                  "removing and resending.\n")

    print(f"\n[=] Bad chars found (beyond pre-excluded "
          f"{[hex(b) for b in sorted(cfg.excluded)]}):")
    print(f"    {[hex(b) for b in sorted(found_bad)]}")
    all_bad = sorted(set(found_bad) | cfg.excluded)
    print(f"[=] Full bad-char set (with exclusions): {[hex(b) for b in all_bad]}")
    return sorted(found_bad)


def _register_reached(cfg, result, test_bytes) -> bool:
    """
    Register oracle: given a crashed RoundResult (which captured the landing
    register's value and, in pointer mode, a memory window around it AT crash
    time), decide whether our buffer reached the register (clean) or a bad byte
    truncated it (dirty).

    Works on the RESULT's captured data, not a live debugger — the debugger is
    already torn down by the time this runs, so the data must have been captured
    during run_one_round while the target was frozen.
    """
    if result.reg_value is None:
        # couldn't read the register at crash time -> can't judge; treat as
        # "not reached" so bisection keeps looking rather than falsely passing.
        return False

    if cfg.register_mode == "pointer":
        data = result.reg_window
        if not data:
            return False
        if cfg.marker in data:
            return True
        if len(test_bytes) >= 8 and test_bytes[:8] in data:
            return True
        return False
    else:  # direct (heuristic — pointer mode is more reliable)
        regbytes = result.reg_value.to_bytes(4, "little")
        return all(b in test_bytes or b == cfg.known_good for b in regbytes)


def _run_register_detection(cfg, session, cands, result, found_bad, bs, crash_timeout_ms) -> bool:
    """Run register-based detection. `result` is the crashed RoundResult for the
    current full candidate set (already captured its register data).
    Returns True if the hunt is complete, False if bad chars were removed."""
    if _register_reached(cfg, result, cands):
        print("[+] All sent bytes reached the register intact. Hunt complete.")
        return True
    print("    -> buffer did not reach the register; bisecting.")
    bad = _bisect_registers(cfg, session, cands, crash_timeout_ms)
    if not bad:
        print("[!] Register bisection found nothing; stopping.")
        return True
    for b in bad:
        if b not in found_bad:
            found_bad.append(b)
            bs.mark_bad(b)
    print(f"    -> bad char(s): {[hex(b) for b in bad]}; resending.\n")
    return False


def _bisect_registers(cfg, session, cands, crash_timeout_ms) -> list:
    """Bisect using the register oracle. Each probe is a full round: crash the
    target (which captures the register data into the RoundResult), then check
    whether the buffer reached the register."""
    if len(cands) == 1:
        return [cands[0]]
    mid = len(cands) // 2
    bad = []
    for half in (cands[:mid], cands[mid:]):
        if not half:
            continue
        print(f"      [reg-bisect] testing {len(half)} bytes ...")
        r = run_one_round(cfg, half, session, crash_timeout_ms=crash_timeout_ms)
        if r.crashed and _register_reached(cfg, r, half):
            print(f"        reached register -> clean group ({len(half)} bytes)")
            continue
        print(f"        did NOT reach register -> bad byte in this group; recursing")
        bad.extend(_bisect_registers(cfg, session, half, crash_timeout_ms))
    return bad


def _bisect_no_crash(cfg: HuntConfig, cands: bytes, session: "DebugSession",
                     crash_timeout_ms) -> list[int]:
    """
    A group of candidate bytes did NOT crash -> a bad byte is inside it. Split
    and recurse: whichever half fails to crash contains a bad byte. Returns the
    isolated bad byte value(s).
    """
    if len(cands) == 1:
        return [cands[0]]        # isolated: this single byte prevents the crash

    mid = len(cands) // 2
    halves = [cands[:mid], cands[mid:]]
    bad: list[int] = []
    for half in halves:
        if not half:
            continue
        print(f"      [bisect] testing {len(half)} bytes ...")
        r = run_one_round(cfg, half, session, crash_timeout_ms=crash_timeout_ms)
        if r.crashed:
            print(f"        crashed -> clean group ({len(half)} bytes)")
            continue
        print(f"        no crash -> bad byte in this group; recursing")
        bad.extend(_bisect_no_crash(cfg, half, session, crash_timeout_ms))
    return bad


if __name__ == "__main__":
    # Full hunt (attach mode). Start the target yourself; give a PID when
    # prompted after each crash (or use a respawn recipe via the console).
    #   python -m badcharhunter.engine <host> <port> [--manual-buffer]
    #
    # --manual-buffer: be asked which marker match to use when several are found
    # (instead of auto-picking the most-aligned copy).
    import sys

    argv = [a for a in sys.argv[1:] if a != "--manual-buffer"]
    manual_buffer = "--manual-buffer" in sys.argv[1:]

    if len(argv) < 2:
        print("usage: engine <host> <port> [--manual-buffer]")
        raise SystemExit(1)

    host = argv[0]
    port = int(argv[1])
    cfg = HuntConfig(host=host, port=port, manual_buffer_select=manual_buffer)
    hunt(cfg)