# BadCharHunter

**Automated bad-character detection for Windows exploit development — with a hand-rolled debugger built on raw Win32.**

Bad characters (bytes that a target mangles, truncates, or rejects) are one of the first things you hunt when developing a memory-corruption exploit. The usual workflow is manual and tedious: send a byte set, crash the target by hand, dump memory in a debugger, eyeball the diff, remove a bad byte, restart everything, repeat. BadCharHunter automates the whole loop — including restarting the target and re-attaching after every crash — and it does its own debugging through the raw Windows debug API.

## What it does

Given a vulnerable network service and the length that crashes it, BadCharHunter:

1. Sends a baseline buffer of known-good bytes and confirms the target crashes.
2. Sends the full candidate byte set and detects bad characters up to three ways:
   - **Memory diff** (when the target crashes and the buffer lands in memory) — it locates the buffer in the crashed process's memory, reads it back, and diffs what was sent against what landed to find corrupted/truncated bytes.
   - **Crash-oracle bisection** (when a bad byte prevents the crash) — it binary-searches the byte set: a group that still crashes is clean, a group that doesn't contains a bad byte. This catches bad chars a memory diff never sees, because there's no crash and nothing to read.
   - **Register-based detection** (when the buffer isn't found in memory at all — e.g. a direct EIP overwrite) — it reads a landing register you specify and checks whether the buffer reached it, bisecting on that signal.
3. Removes each confirmed bad char, regenerates the set, and repeats until the whole set lands intact.
4. Reports the complete bad-char set.

It restarts and re-attaches to the target automatically between crashes, so a full hunt runs hands-off — even against Windows services.

## Why multiple detection methods

A bad byte shows up in incompatible ways, and you need more than one method to be correct:

- It **corrupts the buffer but still crashes** → visible only by reading the landed bytes and diffing (the memory-diff path).
- It **prevents the crash entirely** (breaks the buffer before it reaches crash size) → invisible to a diff (no crash, nothing to read), found only by bisection over crash behavior.
- The **buffer never lands findable in memory** (a direct register/EIP overwrite) → neither a diff nor plain crash-bisection sees it cleanly; register-based detection reads a register the buffer lands in and checks whether it got there.

A crash-oracle-only tool misses the first class; a diff-only tool misses the second; both miss register-overwrite targets. BadCharHunter uses the cheap diff first and falls back as needed.

## Protocols

- **Text templates** for HTTP-like protocols: a request template with a `{{BUF}}` placeholder (and optional `{{LEN}}`) — e.g. `GET /{{BUF}} HTTP/1.1\r\nHost: {{HOST}}\r\n\r\n`.
- **Custom sender functions** for binary protocols the template can't express (packed lengths, checksums, custom framing): supply a small Python file with `send(buffer, host, port)` and it delivers the buffer each round. See `example_sender.py`.

## Automated respawn (services)

A target that crashes has to come back for the next round. A **respawn recipe** (a small script) automates that — restart the service, wait, find its new PID by process name, and re-attach:

```
cmd "net stop \"Some Service\""
cmd "net start \"Some Service\""
sleep 2
get_pid_by_name "target.exe" pid
run pid
```

With a recipe loaded, a full hunt against a service runs with no manual PID entry.

## Register-based detection (buffer-not-found targets)

Some targets overwrite a register directly (a classic direct EIP overwrite) — the buffer doesn't sit intact in a readable region, so the memory-diff can't find it. For these, tell BadCharHunter which register the buffer lands in and how to read it:

- `set landing_register eip` (or `esp`, `eax`, …) — the register the buffer reaches.
- `set register_mode pointer` — the register holds an **address** pointing at the buffer (reads memory there and looks for the marker). **Reliable — prefer this where the target allows.**
- `set register_mode direct` — the register **holds the bytes directly** (e.g. EIP = `0x41414141`). This is a **heuristic** and less reliable than pointer mode.
- `set signature_detection true` — skip buffer-finding entirely and go straight to register-based detection from the start (for targets you already know won't land the buffer).

With `signature_detection` off (the default), BadCharHunter tries the memory-diff first and only falls back to register-based detection if the buffer isn't found and a `landing_register` is set.

## Usage

### Interactive console (recommended)

Launch the console — an msf-style interface where you set options and run:

```
python3 -m badcharhunter.console
```

### Console commands

| Command | What it does |
|---|---|
| `set <option> <value>` | configure an option (host, port, crash_size, template, excluded, …) |
| `show` | show all current settings |
| `set template_file <path>` | load the request template from a file |
| `set sender_file <path.py>` | load a custom `send(buffer, host, port)` for binary protocols |
| `set respawn_recipe <path>` | load a respawn recipe (auto-restart + re-attach) |
| `set landing_register <reg>` | register the buffer lands in (esp/eip/…) — enables register-based detection |
| `set register_mode <mode>` | `pointer` (reliable) or `direct` (heuristic) — how to read the landing register |
| `set signature_detection <bool>` | `true` = skip buffer-finding, use register-based detection only |
| `unset <option>` | clear a setting |
| `run` | build the config and start the hunt |
| `exit` | leave the console |

Required options (no default, must be set): **host**, **port**, **crash_size**.