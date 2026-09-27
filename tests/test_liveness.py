"""Owner identity and PID-reuse-aware liveness checks."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time

import pytest

from aais import liveness
from aais.liveness import (
    START_TIME_TOLERANCE_SECONDS,
    Liveness,
    OwnerIdentity,
    current_host_id,
    owner_liveness,
    pid_liveness,
    process_alive,
    process_start_time,
)


def exited_pid() -> int:
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()
    return process.pid


def test_current_process_is_alive_with_a_plausible_start_time() -> None:
    me = OwnerIdentity.current()
    assert me.pid == os.getpid()
    assert me.process_start_time is not None
    assert 0 <= time.time() - me.process_start_time < 24 * 3600 * 365
    assert owner_liveness(me) is Liveness.ALIVE
    assert me.liveness() is Liveness.ALIVE
    assert OwnerIdentity.current() is me  # cached per PID


def test_exited_process_is_dead() -> None:
    pid = exited_pid()
    assert pid_liveness(pid) is Liveness.DEAD
    assert process_alive(pid) is False
    assert owner_liveness(OwnerIdentity(pid, time.time(), current_host_id())) is Liveness.DEAD


def test_pid_reuse_is_detected_by_start_time() -> None:
    me = OwnerIdentity.current()
    assert me.process_start_time is not None
    reused = OwnerIdentity(
        me.pid, me.process_start_time - 10 * START_TIME_TOLERANCE_SECONDS, me.host_id
    )
    assert owner_liveness(reused) is Liveness.DEAD
    close = OwnerIdentity(
        me.pid, me.process_start_time + START_TIME_TOLERANCE_SECONDS / 2, me.host_id
    )
    assert owner_liveness(close) is Liveness.ALIVE


def test_other_host_is_unknown_never_dead() -> None:
    owner = OwnerIdentity(exited_pid(), 1.0, "host-somewhere-else")
    assert owner_liveness(owner) is Liveness.UNKNOWN
    assert owner_liveness(owner, host_id="host-somewhere-else") is Liveness.DEAD


def test_eperm_counts_as_alive(monkeypatch: pytest.MonkeyPatch) -> None:
    if sys.platform == "win32":
        pytest.skip("POSIX signal semantics")

    def denied(_pid: int, _signal: int) -> None:
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(liveness.os, "kill", denied)
    monkeypatch.setattr(liveness, "_linux_stat_fields", lambda _pid: None)
    assert pid_liveness(424242) is Liveness.ALIVE
    # Start time unreadable too: still not declared dead.
    monkeypatch.setattr(liveness, "process_start_time", lambda _pid: None)
    assert owner_liveness(OwnerIdentity(424242, 5.0, current_host_id())) is Liveness.ALIVE


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs non-root POSIX")
def test_real_eperm_on_init_process() -> None:
    try:
        os.kill(1, 0)
    except PermissionError:
        assert pid_liveness(1) is Liveness.ALIVE
    except ProcessLookupError:  # pragma: no cover - PID namespaces without an init
        pytest.skip("no PID 1 visible")
    else:  # pragma: no cover - PID 1 is ours (container)
        pytest.skip("PID 1 belongs to this user")


def test_unexpected_kill_error_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    if sys.platform == "win32":
        pytest.skip("POSIX signal semantics")

    def weird(_pid: int, _signal: int) -> None:
        raise OSError(22, "Invalid argument")

    monkeypatch.setattr(liveness.os, "kill", weird)
    assert pid_liveness(424242) is Liveness.UNKNOWN
    assert process_alive(424242) is True


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux zombie state")
def test_zombie_process_is_dead() -> None:
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    try:
        deadline = time.monotonic() + 10
        while liveness._linux_stat_fields(process.pid)[0] != "Z":  # type: ignore[index]
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert pid_liveness(process.pid) is Liveness.DEAD
    finally:
        process.wait()


@pytest.mark.parametrize("pid", [None, 0, -1, True, "12"])
def test_invalid_pids(pid: object) -> None:
    assert pid_liveness(pid) is Liveness.DEAD  # type: ignore[arg-type]
    assert process_start_time(pid) is None  # type: ignore[arg-type]


def test_owner_serialization_and_legacy_pid() -> None:
    owner = OwnerIdentity(123, 1700000000.5, "host-a")
    assert OwnerIdentity.from_dict(owner.to_dict()) == owner
    legacy = OwnerIdentity.from_dict(456)
    assert legacy == OwnerIdentity(456, None, current_host_id())
    for bad in (
        {"pid": 0, "host_id": "h"},
        {"pid": 1, "host_id": ""},
        {"pid": 1, "host_id": "h", "process_start_time": "yesterday"},
        {"pid": 1, "host_id": "h", "process_start_time": True},
    ):
        with pytest.raises(ValueError):
            OwnerIdentity.from_dict(bad)
    with pytest.raises(TypeError):
        OwnerIdentity.from_dict("123")  # type: ignore[arg-type]


def test_legacy_owner_without_start_time_uses_pid_only() -> None:
    assert owner_liveness(OwnerIdentity(os.getpid(), None, current_host_id())) is Liveness.ALIVE
    assert owner_liveness(OwnerIdentity(exited_pid(), None, current_host_id())) is Liveness.DEAD


def test_host_id_is_stable_opaque_and_overridable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(liveness.HOST_ID_ENV, raising=False)
    first = current_host_id()
    assert first == current_host_id()
    assert first.startswith("host-") and len(first) == 37
    machine = liveness._read_first_line("/etc/machine-id")
    if machine:
        assert machine not in first
    monkeypatch.setenv(liveness.HOST_ID_ENV, "host-override")
    assert current_host_id() == "host-override"


def test_ps_lstart_parser() -> None:
    assert liveness._parse_ps_lstart("Sat Sep 27 10:00:00 2026\n") == 1790503200.0
    assert liveness._parse_ps_lstart("Sun Sep  6 01:02:03 2026") == 1788656523.0
    assert liveness._parse_ps_lstart("") is None
    assert liveness._parse_ps_lstart("garbage") is None


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("ps") is None, reason="needs a POSIX ps"
)
def test_ps_fallback_matches_native_start_time() -> None:
    via_ps = liveness._ps_start_time(os.getpid())
    assert via_ps is not None
    native = process_start_time(os.getpid())
    assert native is not None
    assert abs(via_ps - native) <= START_TIME_TOLERANCE_SECONDS
    assert liveness._ps_start_time(exited_pid()) is None


def test_filetime_conversion() -> None:
    # 2026-09-27T10:00:00Z expressed as a Windows FILETIME.
    filetime = (1790503200 * 10_000_000) + liveness._FILETIME_EPOCH_OFFSET
    assert liveness._filetime_to_epoch(filetime) == 1790503200.0


@pytest.mark.skipif(sys.platform != "win32", reason="Windows process APIs")
def test_windows_start_time_and_liveness() -> None:  # pragma: no cover - Windows CI
    me = OwnerIdentity.current()
    assert me.process_start_time is not None
    assert owner_liveness(me) is Liveness.ALIVE
    assert pid_liveness(exited_pid()) is Liveness.DEAD
