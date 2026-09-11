# BadCharHunter

**Automated bad-character detection for Windows exploit development — with a hand-rolled debugger built on raw Win32.**

Bad characters (bytes that a target mangles, truncates, or rejects) are one of
the first things you hunt when developing a memory-corruption exploit. The usual
workflow is manual and tedious: send a byte set, crash the target by hand, dump
memory in a debugger, eyeball the diff, remove a bad byte, restart everything,
repeat. BadCharHunter automates the whole loop — including restarting the target
and re-attaching after every crash — and it does its own debugging through the
raw Windows debug API.

## What it does
 
Given a vulnerable network service and the length that crashes it, BadCharHunter:
 
1. Sends a baseline buffer of known-good bytes and confirms the target crashes.
2. Sends the full candidate byte set and detects bad characters two ways:
   - **Memory diff** (when the target crashes) — it locates the buffer in the
     crashed process's memory, reads it back, and diffs what was *sent* against
     what *landed* to find corrupted/truncated bytes.
   - **Crash-oracle bisection** (when a bad byte *prevents* the crash) — it
     binary-searches the byte set: a group that still crashes is clean, a group
     that doesn't contains a bad byte. This catches bad chars a memory diff
     never sees, because there's no crash and nothing to read.
3. Removes each confirmed bad char, regenerates the set, and repeats until the
   whole set lands intact.
4. Reports the complete bad-char set.

It restarts and re-attaches to the target automatically between crashes, so a
full hunt runs hands-off — even against Windows **services**.

## Why two detection methods
 
A bad byte shows up in one of two incompatible ways, and you need both to be
correct:
 
- It **corrupts the buffer but still crashes** → visible only by reading the
  landed bytes and diffing (the memory-diff path).
- It **prevents the crash entirely** (breaks the buffer before it reaches crash
  size) → invisible to a diff (no crash, nothing to read), found only by
  bisection over crash behavior.
A crash-oracle-only tool misses the first class; a diff-only tool misses the
second. BadCharHunter uses the cheap diff first and falls back to bisection.

## Protocols
 
- **Text templates** for HTTP-like protocols: a request template with a
  `{{BUF}}` placeholder (and optional `{{LEN}}`) — e.g.
  `GET /{{BUF}} HTTP/1.1\r\nHost: {{HOST}}\r\n\r\n`.
- **Custom sender functions** for binary protocols the template can't express
  (packed lengths, checksums, custom framing): supply a small Python file with
  `send(buffer, host, port)` and it delivers the buffer each round. See
  `example_sender.py`.

## Automated respawn (services)
 
A target that crashes has to come back for the next round. A **respawn recipe**
(a small script) automates that — restart the service, wait, find its new PID by
process name, and re-attach:
 
```
cmd "net stop \"Some Service\""
cmd "net start \"Some Service\""
sleep 2
get_pid_by_name "target.exe" pid
run pid
```
 
With a recipe loaded, a full hunt against a service runs with no manual PID entry.