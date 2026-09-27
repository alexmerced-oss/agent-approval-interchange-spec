"""Process owner identity and liveness checks that survive PID reuse.

An approval request is owned by the process that is waiting on it. Recording
only the PID is not enough: operating systems reuse PIDs, so a stopped owner can
look alive when an unrelated process later receives the same number. An
:class:`OwnerIdentity` therefore records the PID, the process start time, and a
host identifier. :func:`owner_liveness` compares all three:

* a different host yields :attr:`Liveness.UNKNOWN` (never ``DEAD``), because a
  local PID table says nothing about another machine or PID namespace;
* a missing PID yields :attr:`Liveness.DEAD`;
* a PID that exists but belongs to someone else (``EPERM``) yields
  :attr:`Liveness.ALIVE`;
* a live PID whose start time differs from the recorded one yields
  :attr:`Liveness.DEAD` (the PID was reused).

Everything here uses the standard library only. Linux reads ``/proc``, macOS
and other POSIX systems fall back to ``ps``, and Windows uses ``OpenProcess``
and ``GetProcessTimes`` through :mod:`ctypes`. None of the checks signal or
otherwise disturb the target process.
"""

from __future__ import annotations

import calendar
import enum
import hashlib
import os
import socket
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "START_TIME_TOLERANCE_SECONDS",
    "Liveness",
    "OwnerIdentity",
    "current_host_id",
    "owner_liveness",
    "pid_liveness",
    "process_alive",
    "process_start_time",
]

#: Start times are compared with this tolerance. Linux derives start times from
#: the boot time, which the kernel may report with up to a second of jitter, and
#: ``ps`` reports whole seconds. A PID would have to be recycled within this
#: window to be mistaken for the original owner.
START_TIME_TOLERANCE_SECONDS = 2.0

#: Environment variable that overrides the computed host identifier. Set it to
#: the same value in every process that shares a PID namespace but not a
#: machine id (unusual), or to distinct values to force ``UNKNOWN`` results.
HOST_ID_ENV = "AAIS_HOST_ID"


class Liveness(str, enum.Enum):
    """Result of an ownership liveness check."""

    ALIVE = "alive"
    DEAD = "dead"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------- host id

_HOST_ID_CACHE: str | None = None


def _read_first_line(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as handle:
            value = handle.readline().strip()
    except OSError:
        return None
    return value or None


def _machine_identity() -> str:
    parts: list[str] = [sys.platform]
    machine: str | None = None
    if sys.platform.startswith("linux"):
        machine = _read_first_line("/etc/machine-id") or _read_first_line(
            "/var/lib/dbus/machine-id"
        )
        # Two containers can share a machine id while having separate PID
        # namespaces, so the namespace is part of the identity.
        try:
            parts.append(os.readlink("/proc/self/ns/pid"))
        except OSError:
            pass
    elif sys.platform == "win32":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                machine = str(winreg.QueryValueEx(key, "MachineGuid")[0])
        except OSError:
            machine = None
    elif sys.platform == "darwin":
        try:
            output = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            output = ""
        for line in output.splitlines():
            if "IOPlatformUUID" in line:
                machine = line.split("=", 1)[-1].strip().strip('"') or None
                break
    parts.append(machine or f"hostname:{socket.gethostname()}")
    return "\0".join(parts)


def current_host_id() -> str:
    """Return a stable, opaque identifier for this host and PID namespace.

    The raw machine id is hashed so that it is not written to approval state.
    ``AAIS_HOST_ID`` overrides the computed value.
    """

    global _HOST_ID_CACHE
    override = os.environ.get(HOST_ID_ENV)
    if override:
        return override
    if _HOST_ID_CACHE is None:
        digest = hashlib.sha256(b"aais-host-v1\0" + _machine_identity().encode("utf-8"))
        _HOST_ID_CACHE = "host-" + digest.hexdigest()[:32]
    return _HOST_ID_CACHE


# ------------------------------------------------------------ process queries


def _valid_pid(pid: object) -> bool:
    return isinstance(pid, int) and not isinstance(pid, bool) and pid > 0


def _linux_stat_fields(pid: int) -> list[str] | None:
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as handle:
            raw = handle.read()
    except OSError:
        return None
    # The command name is wrapped in parentheses and may itself contain spaces
    # or parentheses; everything after the last ')' is space separated.
    closing = raw.rfind(")")
    if closing < 0:
        return None
    return raw[closing + 2 :].split()


_LINUX_BOOT_TIME: float | None = None


def _linux_boot_time() -> float | None:
    global _LINUX_BOOT_TIME
    if _LINUX_BOOT_TIME is None:
        try:
            with open("/proc/stat", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("btime "):
                        _LINUX_BOOT_TIME = float(line.split()[1])
                        break
        except (OSError, ValueError, IndexError):
            return None
    return _LINUX_BOOT_TIME


def _linux_start_time(pid: int) -> float | None:
    fields = _linux_stat_fields(pid)
    boot = _linux_boot_time()
    if fields is None or boot is None or len(fields) < 20:
        return None
    try:
        ticks = int(fields[19])  # field 22 of /proc/<pid>/stat
        hertz = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError):
        return None
    return round(boot + ticks / hertz, 2)


def _parse_ps_lstart(text: str) -> float | None:
    """Parse ``ps -o lstart=`` output produced with ``LC_ALL=C TZ=UTC``."""

    cleaned = " ".join(text.split())
    if not cleaned:
        return None
    try:
        parsed = time.strptime(cleaned, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return float(calendar.timegm(parsed))


def _ps_start_time(pid: int) -> float | None:
    env = {"LC_ALL": "C", "LANG": "C", "TZ": "UTC", "PATH": os.environ.get("PATH", "/bin:/usr/bin")}
    try:
        completed = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return _parse_ps_lstart(completed.stdout)


# Windows constants.
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_WAIT_TIMEOUT = 0x00000102
_ERROR_ACCESS_DENIED = 5
#: 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
_FILETIME_EPOCH_OFFSET = 116444736000000000


def _filetime_to_epoch(value: int) -> float:
    """Convert a Windows FILETIME integer to POSIX seconds."""

    return round((value - _FILETIME_EPOCH_OFFSET) / 10_000_000, 2)


if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
    import ctypes
    from ctypes import wintypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    _kernel32.GetProcessTimes.restype = wintypes.BOOL

    def _windows_open(pid: int, access: int) -> tuple[Any, int]:
        handle = _kernel32.OpenProcess(access, False, pid)
        return handle, (0 if handle else ctypes.get_last_error())

    def _windows_liveness(pid: int) -> Liveness:
        handle, error = _windows_open(pid, _SYNCHRONIZE | _PROCESS_QUERY_LIMITED_INFORMATION)
        if not handle:
            # Access denied means the process exists but belongs to someone else.
            return Liveness.ALIVE if error == _ERROR_ACCESS_DENIED else Liveness.DEAD
        try:
            state = _kernel32.WaitForSingleObject(handle, 0)
            return Liveness.ALIVE if state == _WAIT_TIMEOUT else Liveness.DEAD
        finally:
            _kernel32.CloseHandle(handle)

    def _windows_start_time(pid: int) -> float | None:
        handle, _error = _windows_open(pid, _PROCESS_QUERY_LIMITED_INFORMATION)
        if not handle:
            return None
        try:
            created = wintypes.FILETIME()
            exited = wintypes.FILETIME()
            kernel = wintypes.FILETIME()
            user = wintypes.FILETIME()
            ok = _kernel32.GetProcessTimes(
                handle,
                ctypes.byref(created),
                ctypes.byref(exited),
                ctypes.byref(kernel),
                ctypes.byref(user),
            )
            if not ok:
                return None
            value = (created.dwHighDateTime << 32) | created.dwLowDateTime
            return _filetime_to_epoch(value)
        finally:
            _kernel32.CloseHandle(handle)


def process_start_time(pid: int) -> float | None:
    """Return a process start time in POSIX seconds, or ``None`` if unknown."""

    if not _valid_pid(pid):
        return None
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
        return _windows_start_time(pid)
    if sys.platform.startswith("linux"):
        value = _linux_start_time(pid)
        if value is None and not os.path.isdir("/proc/self"):
            value = _ps_start_time(pid)  # /proc is not mounted (rare sandboxes)
        return value
    return _ps_start_time(pid)


def pid_liveness(pid: int | None) -> Liveness:
    """Check a local PID without start-time verification.

    ``EPERM`` (the process exists but belongs to another user) is treated as
    alive. Exited-but-unreaped (zombie) processes on Linux are treated as dead.
    """

    if pid is None or not _valid_pid(pid):
        return Liveness.DEAD
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
        return _windows_liveness(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return Liveness.DEAD
    except PermissionError:
        return Liveness.ALIVE
    except (OSError, ValueError, OverflowError):
        return Liveness.UNKNOWN
    if sys.platform.startswith("linux"):
        fields = _linux_stat_fields(pid)
        if fields and fields[0] in {"Z", "X", "x"}:
            return Liveness.DEAD
    return Liveness.ALIVE


def process_alive(pid: int | None) -> bool:
    """Compatibility helper: ``True`` unless the PID is known to be gone."""

    return pid_liveness(pid) is not Liveness.DEAD


# ------------------------------------------------------------------- identity

_CURRENT: tuple[int, OwnerIdentity] | None = None


@dataclass(frozen=True)
class OwnerIdentity:
    """The process that owns (is waiting on) an approval request."""

    pid: int
    process_start_time: float | None
    host_id: str

    @classmethod
    def current(cls) -> OwnerIdentity:
        """Identity of the calling process (cached per PID, so safe after fork)."""

        global _CURRENT
        pid = os.getpid()
        if _CURRENT is None or _CURRENT[0] != pid:
            _CURRENT = (pid, cls(pid, process_start_time(pid), current_host_id()))
        return _CURRENT[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "process_start_time": self.process_start_time,
            "host_id": self.host_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any] | int) -> OwnerIdentity:
        """Load an identity. A bare integer is a legacy PID-only owner record.

        Legacy owners are assumed to be local and have no start time, so their
        liveness falls back to a PID-only check.
        """

        if isinstance(value, int) and not isinstance(value, bool):
            return cls(value, None, current_host_id())
        if not isinstance(value, Mapping):
            raise TypeError("owner must be an object or a PID")
        pid = value.get("pid")
        start = value.get("process_start_time")
        host = value.get("host_id")
        if not _valid_pid(pid):
            raise ValueError("owner.pid must be a positive integer")
        if start is not None and (isinstance(start, bool) or not isinstance(start, (int, float))):
            raise ValueError("owner.process_start_time must be a number or null")
        if not isinstance(host, str) or not host:
            raise ValueError("owner.host_id must be a non-empty string")
        assert isinstance(pid, int)
        return cls(pid, None if start is None else float(start), host)

    def liveness(self) -> Liveness:
        return owner_liveness(self)


def owner_liveness(owner: OwnerIdentity, *, host_id: str | None = None) -> Liveness:
    """Decide whether ``owner`` is still running, accounting for PID reuse."""

    local = host_id if host_id is not None else current_host_id()
    if owner.host_id != local:
        return Liveness.UNKNOWN
    state = pid_liveness(owner.pid)
    if state is not Liveness.ALIVE or owner.process_start_time is None:
        return state
    observed = process_start_time(owner.pid)
    if observed is None:
        # The PID exists but its start time cannot be read; do not call it dead.
        return Liveness.ALIVE
    if abs(observed - owner.process_start_time) > START_TIME_TOLERANCE_SECONDS:
        return Liveness.DEAD
    return Liveness.ALIVE
