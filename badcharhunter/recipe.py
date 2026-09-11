from __future__ import annotations
import shlex
import subprocess
import time
import re
from dataclasses import dataclass


class RecipeError(Exception):
    """Raised for parse or run errors, with a helpful message."""


@dataclass
class Step:
    verb: str
    literal: str | None      # the quoted argument, if any
    var: str | None          # the bare variable name, if any
    lineno: int
    raw: str


_VERBS = {"cmd", "sleep", "get_pid_by_name", "get_pid_by_func", "run"}


def parse_recipe(text: str) -> list[Step]:
    """
    Parse recipe text into a validated list of Steps. Raises RecipeError with a
    line number on any problem. Blank lines and #-comments are ignored.
    """
    steps: list[Step] = []
    assigned: set[str] = set()
    run_seen = False

    for i, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            tokens = shlex.split(stripped, posix=True)
        except ValueError as e:
            raise RecipeError(f"line {i}: quoting error ({e}): {stripped!r}")
        if not tokens:
            continue

        verb = tokens[0]
        if verb not in _VERBS:
            raise RecipeError(
                f"line {i}: unknown verb {verb!r} "
                f"(expected one of {', '.join(sorted(_VERBS))})")

        # shlex has already stripped the quotes, so we can't tell quoted from
        # bare after the fact. Re-tokenize keeping track: for our fixed grammar
        # the ARG POSITIONS are known per verb, so positional validation is enough.
        args = tokens[1:]

        if verb == "cmd":
            if len(args) != 1:
                raise RecipeError(f'line {i}: cmd needs one quoted command: cmd "..."')
            steps.append(Step("cmd", args[0], None, i, stripped))

        elif verb == "sleep":
            if len(args) != 1:
                raise RecipeError(f"line {i}: sleep needs one number: sleep 2")
            try:
                float(args[0])
            except ValueError:
                raise RecipeError(f"line {i}: sleep value must be a number: {args[0]!r}")
            steps.append(Step("sleep", args[0], None, i, stripped))

        elif verb in ("get_pid_by_name", "get_pid_by_func"):
            if len(args) != 2:
                raise RecipeError(
                    f'line {i}: {verb} needs a quoted arg and a variable: '
                    f'{verb} "..." varname')
            literal, var = args[0], args[1]
            if not _is_identifier(var):
                raise RecipeError(f"line {i}: {var!r} is not a valid variable name")
            steps.append(Step(verb, literal, var, i, stripped))
            assigned.add(var)

        elif verb == "run":
            if len(args) != 1:
                raise RecipeError(f"line {i}: run needs one variable: run pid1")
            var = args[0]
            if not _is_identifier(var):
                raise RecipeError(f"line {i}: {var!r} is not a valid variable name")
            if var not in assigned:
                raise RecipeError(
                    f"line {i}: run references {var!r} which was never assigned "
                    "by a get_pid_by_* step")
            steps.append(Step("run", None, var, i, stripped))
            run_seen = True

    if not run_seen:
        raise RecipeError("recipe has no `run <var>` statement — "
                          "nothing tells the debugger which PID to attach to")
    return steps


def _is_identifier(s: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s))


def run_recipe(steps: list[Step], *, verbose: bool = True) -> int:
    """
    Execute a parsed recipe and return the PID named by its `run` statement.
    Windows-only for get_pid_by_name (imported lazily so parsing works anywhere).
    """
    env: dict[str, int] = {}

    def log(msg):
        if verbose:
            print(f"      [recipe] {msg}")

    for step in steps:
        if step.verb == "cmd":
            log(f"cmd: {step.literal}")
            subprocess.run(step.literal, shell=True)

        elif step.verb == "sleep":
            secs = float(step.literal)
            log(f"sleep {secs}s")
            time.sleep(secs)

        elif step.verb == "get_pid_by_name":
            from .procutil import find_pid_by_name
            pid = find_pid_by_name(step.literal)
            env[step.var] = pid
            log(f"{step.var} = pid {pid} (by name {step.literal!r})")

        elif step.verb == "get_pid_by_func":
            out = subprocess.run(step.literal, shell=True,
                                 capture_output=True, text=True)
            pid = _extract_pid(out.stdout)
            if pid is None:
                raise RecipeError(
                    f"line {step.lineno}: get_pid_by_func produced no PID. "
                    f"stdout was: {out.stdout!r}")
            env[step.var] = pid
            log(f"{step.var} = pid {pid} (from func)")

        elif step.verb == "run":
            pid = env.get(step.var)
            if pid is None:
                raise RecipeError(f"line {step.lineno}: {step.var!r} has no value at run")
            log(f"run -> attach pid {pid}")
            return pid

    raise RecipeError("recipe finished without a run statement")


def _extract_pid(stdout: str):
    """Lenient: find the first integer in the command's stdout."""
    m = re.search(r"\d+", stdout or "")
    return int(m.group()) if m else None


def load_recipe_file(path: str) -> list[Step]:
    with open(path, "r", encoding="utf-8") as f:
        return parse_recipe(f.read())


if __name__ == "__main__":
    # Parse-check a recipe file (does NOT execute it):
    #   python -m badcharhunter.recipe <recipe_file>
    import sys
    if len(sys.argv) < 2:
        print("usage: recipe <recipe_file>   (parse-checks only, does not run)")
        raise SystemExit(1)
    try:
        steps = load_recipe_file(sys.argv[1])
    except (RecipeError, OSError) as e:
        print(f"[!] {e}")
        raise SystemExit(1)
    print(f"[+] recipe OK: {len(steps)} steps")
    for s in steps:
        print(f"    {s.lineno}: {s.raw}")