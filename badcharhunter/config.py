from __future__ import annotations
from dataclasses import dataclass, field

BUF_TOKEN = b"{{BUF}}"
LEN_TOKEN = b"{{LEN}}"

# A distinctive, bad-char-free default marker (printable, no 0x00/0x0a/0x0d).
DEFAULT_MARKER = b"BCHM4RK"


@dataclass
class HuntConfig:
    # --- target / network ---
    host: str
    port: int
    crash_size: int                             # total buffer length to fault

    template: bytes = b"{{BUF}}"   # 
    recv_after: bool = True                           # POC reads a response
    timeout: float = 5.0

    # --- byte-hunt tuning ---
    known_good: int = 0x41                             # padding byte ('A')
    marker: bytes = DEFAULT_MARKER
    excluded: set[int] = field(default_factory=lambda: {0x00, 0x0a, 0x0d})

    # --- debugger ---
    mode: str = "attach"                               # "attach" or "launch"
    exe_path: str | None = None                       # for launch mode
    pid: int | None = None                            # initial pid for attach mode

    # --- behavior ---
    manual_buffer_select: bool = False                 # when multiple marker
    #   matches are found, ask the operator which address to use instead of
    #   auto-picking the most-aligned one.
    respawn_recipe: object = None                       # parsed recipe steps
    #   (from recipe.py). When set, a fresh target after a crash is obtained by
    #   running the recipe (restart service, resolve PID, attach) — no prompt.
    #   Replaces the manual PID prompt in attach mode.
    sender_fn: object = None                            # user-supplied callable
    #   send(buffer, host, port) that delivers the buffer to the target however
    #   the protocol needs (binary headers, packed lengths, custom sockets).
    #   When set, it REPLACES the template/connection send path entirely — used
    #   for binary/non-HTTP protocols the text template can't express.
    crash_timeout_ms: int = 3000                        # how long to wait for a
    #   crash before treating a round as "no crash". Too short = real (slow)
    #   crashes misread as no-crash -> false bisection. Bump it if the same
    #   payload crashes inconsistently.

    # --- register-based detection (for targets where the buffer isn't found in
    #     memory, e.g. a direct EIP overwrite) ---
    landing_register: str | None = None                 # e.g. "esp" / "eip"
    register_mode: str = "pointer"                       # "pointer" or "direct"
    signature_detection: bool = False                    # when True, skip buffer
    #   finding entirely and go straight to register/signature detection. When
    #   False (default), try the memory-diff first and only fall back if the
    #   buffer isn't found.

    def __post_init__(self) -> None:
        if self.register_mode not in ("pointer", "direct"):
            raise ValueError("register_mode must be 'pointer' or 'direct'")
        if self.signature_detection and not self.landing_register:
            raise ValueError(
                "signature_detection is on but no landing_register is set "
                "(set landing_register, e.g. 'esp')")
        # Resolve the fixed, one-time {{HOST}} placeholder now (it never changes
        # per round, unlike {{BUF}}/{{LEN}} which connection.py does per send).
        if b"{{HOST}}" in self.template:
            self.template = self.template.replace(b"{{HOST}}",
                                                  str(self.host).encode())

        # The template is only used when there's no custom sender_fn. When a
        # sender_fn is set it delivers the buffer itself, so the template (and
        # its {{BUF}} requirement) doesn't apply.
        if self.sender_fn is None and BUF_TOKEN not in self.template:
            raise ValueError(f"template must contain {BUF_TOKEN.decode()}")
        if not 0x00 <= self.known_good <= 0xFF:
            raise ValueError("known_good must be a byte value 0x00-0xff")
        if self.known_good in self.excluded:
            raise ValueError(
                f"known_good 0x{self.known_good:02x} is in the excluded (bad) set — "
                "padding would poison every round"
            )
        # marker must not contain any excluded (bad) byte, or the search target
        # itself could be corrupted / not land intact.
        bad_in_marker = sorted(set(self.marker) & self.excluded)
        if bad_in_marker:
            raise ValueError(
                "marker contains excluded byte(s): "
                + ",".join(f"0x{b:02x}" for b in bad_in_marker)
            )
        if self.mode not in ("attach",):
            raise ValueError("mode must be 'attach'")
        if self.mode == "launch" and not self.exe_path:
            raise ValueError("launch mode needs exe_path")
        if self.crash_size < len(self.marker) + 1:
            raise ValueError("crash_size too small to hold marker + any test bytes")

    def show(self) -> str:
        """Human-readable options dump (for logs and the console's 'show')."""
        exc = ",".join(f"0x{b:02x}" for b in sorted(self.excluded)) or "(none)"
        lines = [
            "Hunt options:",
            f"  host        = {self.host}",
            f"  port        = {self.port}",
            f"  template    = {self.template!r}",
            f"  crash_size  = {self.crash_size}",
            f"  recv_after  = {self.recv_after}",
            f"  known_good  = 0x{self.known_good:02x}",
            f"  marker      = {self.marker!r}",
            f"  excluded    = {exc}",
            f"  mode        = {self.mode}",
            f"  exe_path    = {self.exe_path}",
            f"  pid         = {self.pid}",
            f"  manual_buffer_select = {self.manual_buffer_select}",
            f"  respawn_recipe = {'loaded' if self.respawn_recipe else '(none)'}",
            f"  sender_fn   = {'loaded (custom send)' if self.sender_fn else '(none, uses template)'}",
            f"  landing_register = {self.landing_register or '(none)'}",
            f"  register_mode = {self.register_mode}",
            f"  signature_detection = {self.signature_detection}",
        ]
        return "\n".join(lines)