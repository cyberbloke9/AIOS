"""Single-writer advisory file lock (Runtime §5.1, sprint 13).

Runtime Protocol §5.1:
    "Active segment file carries a POSIX advisory exclusive lock
    (fcntl F_SETLK) or equivalent Windows file lock. A lock file
    log.lock in the log directory contains the PID and start time of
    the current writer."

Design: the lock file and the holder-info file are kept separate.
  - `<path>`         the zero/one-byte file whose OS lock we hold.
  - `<path>.holder`  sibling text file with PID + ts, readable by
                     anyone who wants to diagnose contention.

Separation matters because Windows' `msvcrt.locking` blocks reads of
the locked byte range even from other handles. A sibling file
sidesteps that without weakening enforcement (enforcement is the OS
lock, not the text file).

  - POSIX: `fcntl.flock(fd, LOCK_EX | LOCK_NB)`
  - Windows: `msvcrt.locking(fd, LK_NBLCK, 1)` on one byte.

Because both are OS-enforced per-process locks, a crashing writer
releases the lock automatically — no stale-takeover logic needed.
"""
from __future__ import annotations

import dataclasses as dc
import os
import sys
import time
from pathlib import Path

_IS_WINDOWS = sys.platform.startswith("win") or os.name == "nt"


class LockContentionError(RuntimeError):
    """Raised when the lock is held by another process."""


@dc.dataclass(frozen=True)
class LockInfo:
    pid: int | None
    acquired_ts_ns: int | None
    raw: str


class FileLock:
    """Advisory exclusive file lock. Non-blocking acquire."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self._holder_path = self.path.with_suffix(self.path.suffix + ".holder") \
            if self.path.suffix else Path(str(self.path) + ".holder")
        self._fd: int | None = None
        self._held: bool = False

    # ------------------------------------------------------------------
    # Acquire / release
    # ------------------------------------------------------------------

    def acquire(self) -> None:
        if self._held:
            raise RuntimeError(f"lock already acquired by this instance: {self.path}")

        self.path.parent.mkdir(parents=True, exist_ok=True)

        flags = os.O_RDWR | os.O_CREAT
        self._fd = os.open(str(self.path), flags, 0o644)

        try:
            if _IS_WINDOWS:
                self._acquire_windows()
            else:
                self._acquire_posix()
        except Exception:
            os.close(self._fd)
            self._fd = None
            raise

        self._write_holder_record()
        self._held = True

    def _acquire_posix(self) -> None:
        import fcntl
        assert self._fd is not None
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            info = self._read_holder_file()
            raise LockContentionError(
                f"lock {self.path} held by PID={info.pid} "
                f"acquired_ts_ns={info.acquired_ts_ns}"
            ) from e

    def _acquire_windows(self) -> None:
        import msvcrt
        assert self._fd is not None
        os.lseek(self._fd, 0, os.SEEK_END)
        size = os.lseek(self._fd, 0, os.SEEK_CUR)
        if size == 0:
            os.write(self._fd, b"\0")
            os.fsync(self._fd)
        os.lseek(self._fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
        except OSError as e:
            info = self._read_holder_file()
            raise LockContentionError(
                f"lock {self.path} held by PID={info.pid} "
                f"acquired_ts_ns={info.acquired_ts_ns}"
            ) from e

    def release(self) -> None:
        if not self._held:
            return
        assert self._fd is not None
        try:
            if _IS_WINDOWS:
                import msvcrt
                os.lseek(self._fd, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass  # best-effort; close releases all locks anyway
            else:
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None
            self._held = False
            # Clear the holder file: caller knows the lock is free now.
            try:
                self._holder_path.unlink()
            except FileNotFoundError:
                pass

    # ------------------------------------------------------------------
    # Holder record in a sibling file (not locked)
    # ------------------------------------------------------------------

    def _write_holder_record(self) -> None:
        record = f"{os.getpid()} {time.time_ns()}\n"
        # Writing the sibling file (not the lock byte itself) is safe on
        # Windows — no range is locked on this path.
        self._holder_path.write_text(record, encoding="ascii")

    def _read_holder_file(self) -> LockInfo:
        try:
            raw = self._holder_path.read_text(encoding="ascii", errors="replace")
        except FileNotFoundError:
            return LockInfo(pid=None, acquired_ts_ns=None, raw="")
        except PermissionError:
            return LockInfo(pid=None, acquired_ts_ns=None, raw="")
        parts = raw.strip().split()
        pid = int(parts[0]) if parts and parts[0].isdigit() else None
        ts_ns = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
        return LockInfo(pid=pid, acquired_ts_ns=ts_ns, raw=raw)

    def info(self) -> LockInfo:
        """Read the current holder record without taking the lock.

        Useful for diagnosing contention from another process. Returns
        empty LockInfo if the holder file is missing or unreadable.
        """
        return self._read_holder_file()

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()

    def is_held(self) -> bool:
        return self._held
