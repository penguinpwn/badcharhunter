from __future__ import annotations
import cmd
import shlex

from .config import HuntConfig, DEFAULT_MARKER
from .engine import hunt


# Settings the user can `set`, with how to parse each from a string.
def _parse_int(s):        return int(s, 0)          # accepts 80 or 0x50
def _parse_template(s):
    # Interpret escape sequences so a typed "\r\n" becomes real CRLF bytes
    # (0x0d 0x0a), not the literal 4 characters \ r \ n. Without this, a
    # console-typed HTTP template would have no real line endings.
    return s.encode().decode("unicode_escape").encode("latin-1")
def _parse_byte(s):       return int(s, 0) & 0xFF    # a single 0x.. byte value
def _parse_bool(s):       return s.lower() in ("1", "true", "yes", "on", "y")
def _parse_byteset(s):
    # "00,0a,0d" or "0x00 0x0a" -> {0,10,13}
    parts = s.replace(",", " ").split()
    return {int(p, 16) if not p.lower().startswith("0x") else int(p, 0) for p in parts}


def _fmt_value(name, value):
    """Display helper — show byte sets and byte values in hex, not decimal."""
    if name == "excluded" and isinstance(value, (set, frozenset)):
        return "{" + ", ".join(f"0x{b:02x}" for b in sorted(value)) + "}"
    if name == "known_good" and isinstance(value, int):
        return f"0x{value:02x}"
    return repr(value)


# name -> (parser, help text). These map onto HuntConfig fields.
SETTINGS = {
    "host":        (str,          "target IP / hostname"),
    "port":        (_parse_int,   "target TCP port"),
    "template":    (_parse_template, "request template with {{BUF}} (and optional {{LEN}}); \\r\\n become real CRLF"),
    "crash_size":  (_parse_int,   "total buffer length that triggers the fault"),
    "recv_after":  (_parse_bool,  "read one response after sending (true/false)"),
    "timeout":     (float,        "socket timeout seconds"),
    "known_good":  (_parse_byte,  "padding byte value, e.g. 0x41"),
    "marker":      (lambda s: s.encode(), "distinctive bad-char-free marker string"),
    "excluded":    (_parse_byteset,"bytes known bad, e.g. 00,0a,0d"),
    "manual_buffer_select": (_parse_bool, "ask which match to use when several (true/false)"),
    "landing_register": (str, "register the buffer lands in (esp/eip/eax...); enables register-based detection"),
    "register_mode": (str, "pointer or direct — how to read the landing register"),
    "signature_detection": (_parse_bool, "true = skip buffer-finding, use register/signature detection only"),
}
_FILE_LOADERS = {
        "template_file": "do_template_file",
        "sender_file":   "do_sender_file",
        "respawn_recipe": "do_respawn_recipe",
    }


class BadCharConsole(cmd.Cmd):
    intro = ("BadCharHunter console. Type 'help' or '?' for commands.\n"
             "Set options (set host ..., set port ...), then 'run'.")
    prompt = "bch > "

    def __init__(self):
        super().__init__()
        self._recipe_path = None   # path of the loaded respawn_recipe, for show
        self._sender_path = None   # path of the loaded sender_file, for show
        # loose settings; sensible defaults for the SAFE, non-target-specific
        # options. host, port, crash_size are intentionally NOT defaulted —
        # they're required and target-specific (see do_run).
        self.settings: dict = {
            "template": b"{{BUF}}",
            "recv_after": True,
            "known_good": 0x41,
            "marker": DEFAULT_MARKER,
            "excluded": {0x00, 0x0a, 0x0d},
            "manual_buffer_select": False,
        }

    def emptyline(self):
        """Pressing Enter on a blank line does nothing (don't repeat last cmd)."""
        pass

    # ---- set ----
    def do_set(self, arg):
        """set <option> <value>   e.g. set host 192.168.1.5"""
        try:
            name, value = arg.split(None, 1)
        except ValueError:
            print("usage: set <option> <value>  (see 'show options')")
            return
        name = name.strip()
 
        # Delegate file-loader names to their dedicated command.
        if name in _FILE_LOADERS:
            print(f"[i] '{name}' loads a file — running '{name} {value.strip()}'")
            getattr(self, _FILE_LOADERS[name])(value.strip())
            return
 
        if name not in SETTINGS:
            print(f"unknown option '{name}'. Options: {', '.join(SETTINGS)}")
            return
        parser, _ = SETTINGS[name]
        try:
            self.settings[name] = parser(value.strip())
        except Exception as e:
            print(f"could not parse value for {name}: {e}")
            return
        print(f"{name} => {_fmt_value(name, self.settings[name])}")
 
    def complete_set(self, text, line, begidx, endidx):
        return [n for n in list(SETTINGS) + list(_FILE_LOADERS)
                if n.startswith(text)]

    # ---- template from file ----
    def do_template_file(self, arg):
        """template_file <path>   load the request template from a file.

        The file may contain either real CRLF line endings OR the literal text
        \\r\\n (backslash-r-backslash-n) — if literal escape sequences are
        present, they're converted to real bytes on load, so an HTTP template
        written with visible \\r\\n works as expected.
        """
        path = arg.strip().strip('"').strip("'")
        if not path:
            print("usage: template_file <path>")
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            print(f"could not read template file: {e}")
            return

        # If the file contains literal escape text like \r or \n (backslash
        # followed by the letter), interpret those escapes into real bytes.
        # A file with genuine CRLF bytes has no literal backslash-r/n, so this
        # only fires when the user wrote the escapes as text.
        if b"\\r" in data or b"\\n" in data or b"\\x" in data or b"\\t" in data:
            try:
                data = data.decode("latin-1").encode("latin-1").decode(
                    "unicode_escape").encode("latin-1")
                print("[i] interpreted literal escape sequences (\\r\\n etc.) "
                      "into real bytes.")
            except Exception as e:
                print(f"[!] could not interpret escapes, using raw bytes: {e}")

        if b"{{BUF}}" not in data:
            print("[!] warning: template file has no {{BUF}} placeholder — "
                  "the tool won't know where the buffer goes.")
        self.settings["template"] = data
        print(f"template loaded from {path} ({len(data)} bytes)")

    # ---- custom sender function (binary / non-HTTP protocols) ----
    def do_sender_file(self, arg):
        """sender_file <path.py>   load a custom send(buffer, host, port) function.

        For protocols the text template can't express (binary headers, packed
        lengths, checksums). The .py file must define a function `send` taking
        (buffer, host, port); the tool calls it each round with the buffer
        (marker + test bytes + padding). When set, it replaces the template.

        SECURITY: this executes the .py file. Only load senders you wrote.
        """
        path = arg.strip().strip('"').strip("'")
        if not path:
            print("usage: sender_file <path.py>")
            return
        import importlib.util
        try:
            spec = importlib.util.spec_from_file_location("bch_user_sender", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except (OSError, Exception) as e:
            print(f"[!] could not load sender file: {e}")
            return
        fn = getattr(module, "send", None)
        if not callable(fn):
            print("[!] the file must define a callable `send(buffer, host, port)`")
            return
        self.settings["sender_fn"] = fn
        self._sender_path = path
        print(f"custom sender loaded from {path}. It will deliver the buffer "
              "each round (template bypassed).")

    def do_unset_sender(self, arg):
        """unset_sender   remove the custom sender (back to the template)"""
        if "sender_fn" in self.settings:
            del self.settings["sender_fn"]
            self._sender_path = None
            print("custom sender removed; back to the template send path.")
        else:
            print("no custom sender was set.")

    # ---- attach / respawn script ----
    def do_respawn_recipe(self, arg):
        """respawn_recipe <path>   load a respawn recipe (parse-checked now).

        When set, a fresh target after each crash is obtained by running this
        recipe (restart the service, resolve its PID, attach) instead of
        prompting you for a PID. See recipe.py for the grammar.
        """
        path = arg.strip().strip('"').strip("'")
        if not path:
            print("usage: respawn_recipe <path>")
            return
        from .recipe import load_recipe_file, RecipeError
        try:
            steps = load_recipe_file(path)
        except (RecipeError, OSError) as e:
            print(f"[!] {e}")
            return
        self.settings["respawn_recipe"] = steps
        self._recipe_path = path
        print(f"attach script loaded from {path} ({len(steps)} steps). "
              "Fresh targets after a crash will run it automatically.")

    def do_unset_script(self, arg):
        """unset_script   remove the respawn recipe (back to manual PID prompts)"""
        if "respawn_recipe" in self.settings:
            del self.settings["respawn_recipe"]
            self._recipe_path = None
            print("respawn recipe removed; back to manual PID prompts.")
        else:
            print("no respawn recipe was set.")

    # ---- unset ----
    def do_unset(self, arg):
        """unset <option>   remove a setting (revert to config default)"""
        name = arg.strip()
 
        # Delegate loader names (or their storage keys) to the dedicated unset
        # commands, which also clear the remembered file path.
        loader_aliases = {
            "template_file": "template",
            "sender_file":   "sender_fn",
            "sender_fn":     "sender_fn",
            "respawn_recipe": "respawn_recipe",
            "respawn_recipe":"respawn_recipe",
        }
        if name in loader_aliases:
            key = loader_aliases[name]
            if key == "sender_fn":
                return self.do_unset_sender("")
            if key == "respawn_recipe":
                return self.do_unset_script("")
            # else falls through to plain removal of "template"
            name = key
 
        if name in self.settings:
            del self.settings[name]
            print(f"{name} unset")
        else:
            print(f"{name} was not set")

    # ---- show ----
    def do_show(self, arg):
        """show [options]   display current settings"""
        required = {"host", "port", "crash_size"}
        sender_active = self.settings.get("sender_fn") is not None
        print("Current settings (built into a HuntConfig at 'run'):")
        for name in SETTINGS:
            # When a custom sender is loaded it delivers the buffer itself, so the
            # template is not used — mark it bypassed instead of showing it as active.
            if name == "template" and sender_active:
                print(f"  {name:22} = (bypassed — custom sender_fn in use)")
                continue
            if name in self.settings:
                print(f"  {name:22} = {_fmt_value(name, self.settings[name])}")
            elif name in required:
                print(f"  {name:22} = (REQUIRED — not set)")
            else:
                print(f"  {name:22} = (default)")
        # respawn_recipe is loaded via `respawn_recipe`, not `set`, so it isn't in
        # SETTINGS — report it separately so you can confirm it's loaded.
        recipe = self.settings.get("respawn_recipe")
        if recipe:
            src = f" from {self._recipe_path}" if self._recipe_path else ""
            print(f"  {'respawn_recipe':22} = loaded ({len(recipe)} steps){src} "
                  "[via respawn_recipe]")
        else:
            print(f"  {'respawn_recipe':22} = (none) [set with respawn_recipe]")
        sender = self.settings.get("sender_fn")
        if sender:
            src = f" ({self._sender_path})" if self._sender_path else ""
            print(f"  {'sender_file':22} = CUSTOM sender_fn in use{src} — template ignored")
        else:
            print(f"  {'sender_file':22} = template (no custom sender)")

    # ---- run ----
    def do_run(self, arg):
        """run   build the config from current settings and start the hunt"""
        # Required, target-specific fields — never silently defaulted, because a
        # wrong value gives wrong/no results without the user realizing why.
        missing = [f for f in ("host", "port", "crash_size")
                   if f not in self.settings]
        if missing:
            for f in missing:
                print(f"[!] {f} is required. set {f} <value>")
            return

        built = dict(self.settings)
        try:
            cfg = HuntConfig(**built)          # construction validates + resolves {{HOST}}
        except TypeError as e:
            print(f"[!] bad settings: {e}")
            return
        except ValueError as e:
            print(f"[!] invalid config: {e}")
            return

        try:
            hunt(cfg)
        except KeyboardInterrupt:
            print("\n[!] hunt interrupted.")

    do_exploit = do_run   # msf muscle memory

    def do_clear(self, arg):
        """clear   clear the terminal screen"""
        import os
        os.system("cls" if os.name == "nt" else "clear")
    do_cls = do_clear   # windows muscle memory

    # ---- exit ----
    def do_exit(self, arg):
        """exit   leave the console"""
        print("bye.")
        return True
    do_quit = do_exit
    do_EOF = do_exit


def main():
    try:
        BadCharConsole().cmdloop()
    except KeyboardInterrupt:
        print("\nbye.")


if __name__ == "__main__":
    main()