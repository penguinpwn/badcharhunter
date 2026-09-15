from __future__ import annotations
import ctypes

from . import win32 as w

_REGISTERS = {
    "eip": "Eip", "esp": "Esp", "ebp": "Ebp",
    "eax": "Eax", "ebx": "Ebx", "ecx": "Ecx", "edx": "Edx",
    "esi": "Esi", "edi": "Edi",
}


def read_registers(thread_handle) -> "w.CONTEXT":
    ctx = w.CONTEXT()
    ctx.ContextFlags = w.CONTEXT_FULL
    if not w.kernel32.GetThreadContext(thread_handle, ctypes.byref(ctx)):
        raise OSError(f"GetThreadContext failed (err={w.last_error()})")
    return ctx


def read_register(thread_handle, name: str) -> int:
    key = name.lower()
    if key not in _REGISTERS:
        raise ValueError(
            f"unknown register {name!r}; supported: {', '.join(sorted(_REGISTERS))}")
    return getattr(read_registers(thread_handle), _REGISTERS[key])


def supported_registers() -> list:
    return sorted(_REGISTERS)