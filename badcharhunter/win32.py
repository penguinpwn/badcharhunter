from __future__ import annotations
import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ---- debug event codes ----
EXCEPTION_DEBUG_EVENT      = 1
CREATE_THREAD_DEBUG_EVENT  = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT    = 4
EXIT_PROCESS_DEBUG_EVENT   = 5
LOAD_DLL_DEBUG_EVENT       = 6
UNLOAD_DLL_DEBUG_EVENT     = 7
OUTPUT_DEBUG_STRING_EVENT  = 8
RIP_EVENT                  = 9

# ---- exception codes we care about ----
EXCEPTION_ACCESS_VIOLATION   = 0xC0000005
EXCEPTION_BREAKPOINT         = 0x80000003
EXCEPTION_GUARD_PAGE         = 0x80000001
EXCEPTION_STACK_OVERFLOW     = 0xC00000FD
EXCEPTION_ILLEGAL_INSTRUCTION= 0xC000001D

# ---- continue status ----
DBG_CONTINUE              = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

# ---- wait sentinel ----
INFINITE = 0xFFFFFFFF

# ---- process access rights for OpenProcess ----
PROCESS_VM_READ           = 0x0010   # ReadProcessMemory
PROCESS_VM_WRITE          = 0x0020   # WriteProcessMemory (with VM_OPERATION)
PROCESS_VM_OPERATION      = 0x0008   # required alongside VM_WRITE
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_TERMINATE         = 0x0001   # TerminateProcess

# Combined rights for a borrowed handle that must serve both read and write.
PROCESS_RW_ALL = (
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
    | PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE
)

# ---- CreateProcess creation flags ----
DEBUG_PROCESS             = 0x00000001  # debug target AND its children
DEBUG_ONLY_THIS_PROCESS   = 0x00000002  # debug only the launched process

# ---- Toolhelp snapshot (process enumeration) ----
TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260

# ---- memory state (MEMORY_BASIC_INFORMATION.State) ----
MEM_COMMIT  = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE    = 0x10000

# ---- memory protection (MEMORY_BASIC_INFORMATION.Protect) ----
PAGE_NOACCESS          = 0x01
PAGE_READONLY          = 0x02
PAGE_READWRITE         = 0x04
PAGE_WRITECOPY         = 0x08
PAGE_EXECUTE           = 0x10
PAGE_EXECUTE_READ      = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD             = 0x100   # reading one raises a guard-page exception
PAGE_NOCACHE           = 0x200
PAGE_WRITECOMBINE      = 0x400

# Protections that permit reading (any of these bits set = readable).
_READABLE_PROTECTS = (
    PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
    | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
)


def is_readable_region(state: int, protect: int) -> bool:
    """
    True if a region can actually be read: committed, a read-capable
    protection, and NOT a guard page (guard pages fault on access).
    """
    if state != MEM_COMMIT:
        return False
    if protect & PAGE_GUARD:
        return False
    if protect & PAGE_NOACCESS:
        return False
    return bool(protect & _READABLE_PROTECTS)


class EXCEPTION_RECORD(ctypes.Structure):
    pass


EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode",        wintypes.DWORD),
    ("ExceptionFlags",       wintypes.DWORD),
    ("ExceptionRecord",      ctypes.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress",     ctypes.c_void_p),
    ("NumberParameters",     wintypes.DWORD),
    ("ExceptionInformation", ctypes.c_void_p * 15),
]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD),
        ("dwFirstChance",   wintypes.DWORD),
    ]


class _DEBUG_EVENT_UNION(ctypes.Union):
    # Only the Exception arm is spelled out; the rest of the union is covered by
    # a raw byte pad so the overall DEBUG_EVENT size is correct. Other arms
    # (CreateProcess, LoadDll, ...) can be added as fields when needed.
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("_pad",      ctypes.c_byte * 160),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId",      wintypes.DWORD),
        ("dwThreadId",       wintypes.DWORD),
        ("u",                _DEBUG_EVENT_UNION),
    ]


class STARTUPINFOW(ctypes.Structure):
    """STARTUPINFO for CreateProcessW. We only need cb set; the rest zeroed."""
    _fields_ = [
        ("cb",              wintypes.DWORD),
        ("lpReserved",      wintypes.LPWSTR),
        ("lpDesktop",       wintypes.LPWSTR),
        ("lpTitle",         wintypes.LPWSTR),
        ("dwX",             wintypes.DWORD),
        ("dwY",             wintypes.DWORD),
        ("dwXSize",         wintypes.DWORD),
        ("dwYSize",         wintypes.DWORD),
        ("dwXCountChars",   wintypes.DWORD),
        ("dwYCountChars",   wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags",         wintypes.DWORD),
        ("wShowWindow",     wintypes.WORD),
        ("cbReserved2",     wintypes.WORD),
        ("lpReserved2",     ctypes.c_void_p),
        ("hStdInput",       wintypes.HANDLE),
        ("hStdOutput",      wintypes.HANDLE),
        ("hStdError",       wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    """Filled by CreateProcess: the handles + ids of the new process/thread."""
    _fields_ = [
        ("hProcess",    wintypes.HANDLE),
        ("hThread",     wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId",  wintypes.DWORD),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """
    Filled by VirtualQueryEx: describes one region of a process's address space.
    Pointer-sized fields use c_void_p / c_size_t so the x64 layout is correct.
    """
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1",      wintypes.DWORD),   # x64 padding
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
        ("__alignment2",      wintypes.DWORD),   # x64 padding
    ]


class PROCESSENTRY32W(ctypes.Structure):
    """Filled by Process32FirstW/NextW when walking a process snapshot."""
    _fields_ = [
        ("dwSize",              wintypes.DWORD),
        ("cntUsage",            wintypes.DWORD),
        ("th32ProcessID",       wintypes.DWORD),
        ("th32DefaultHeapID",   ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID",        wintypes.DWORD),
        ("cntThreads",          wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             wintypes.DWORD),
        ("szExeFile",           ctypes.c_wchar * MAX_PATH),
    ]


# ---- function prototypes (explicit argtypes/restype avoid silent truncation) ----
kernel32.DebugActiveProcess.argtypes = [wintypes.DWORD]
kernel32.DebugActiveProcess.restype  = wintypes.BOOL

kernel32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
kernel32.DebugActiveProcessStop.restype  = wintypes.BOOL

kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wintypes.DWORD]
kernel32.WaitForDebugEvent.restype  = wintypes.BOOL

kernel32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
kernel32.ContinueDebugEvent.restype  = wintypes.BOOL

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype  = wintypes.HANDLE

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype  = wintypes.BOOL

# ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, *lpNumberOfBytesRead)
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

# WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, *lpNumberOfBytesWritten)
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

# CreateProcessW(appName, cmdLine, procAttrs, threadAttrs, inheritHandles,
#                creationFlags, environment, currentDir, *startupInfo, *procInfo)
kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
    wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL

kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype  = wintypes.BOOL

# VirtualQueryEx(hProcess, lpAddress, *lpBuffer, dwLength) -> bytes written (SIZE_T)
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

# Process enumeration via a toolhelp snapshot.
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype  = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype  = wintypes.BOOL

kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype  = wintypes.BOOL


def last_error() -> int:
    return ctypes.get_last_error()


if __name__ == "__main__":
    # Struct self-check. On a real Windows build these sizes must look sane;
    # a DEBUG_EVENT that's too small is the classic manual-ctypes bug.
    print("DEBUG_EVENT size:        ", ctypes.sizeof(DEBUG_EVENT))
    print("EXCEPTION_DEBUG_INFO size:", ctypes.sizeof(EXCEPTION_DEBUG_INFO))
    print("EXCEPTION_RECORD size:   ", ctypes.sizeof(EXCEPTION_RECORD))
    print("STARTUPINFOW size:       ", ctypes.sizeof(STARTUPINFOW))
    print("PROCESS_INFORMATION size:", ctypes.sizeof(PROCESS_INFORMATION))
    print("MEMORY_BASIC_INFO size:  ", ctypes.sizeof(MEMORY_BASIC_INFORMATION))
    print("pointer size (arch):     ", ctypes.sizeof(ctypes.c_void_p))