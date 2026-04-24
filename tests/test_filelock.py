"""Tests for the portable single-writer file lock (§5.1)."""
from __future__ import annotations

import os
import tempfile
import threading
from pathlib import Path

import pytest

from aios.runtime.filelock import FileLock, LockContentionError


def test_acquire_release_basic():
    with tempfile.TemporaryDirectory() as tmp:
        lock = FileLock(Path(tmp) / "log.lock")
        assert not lock.is_held()
        lock.acquire()
        assert lock.is_held()
        lock.release()
        assert not lock.is_held()


def test_context_manager():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "log.lock"
        with FileLock(path) as lock:
            assert lock.is_held()
        # After exit the lock is released; a new FileLock can acquire
        with FileLock(path):
            pass


def test_pid_record_written_on_acquire():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "log.lock"
        with FileLock(path):
            info = FileLock(path).info()
            assert info.pid == os.getpid()
            assert info.acquired_ts_ns is not None
            assert info.acquired_ts_ns > 0


def test_second_acquire_on_held_lock_refused_same_process():
    """Two FileLock instances on the same file in the same process must
    not both hold it simultaneously."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "log.lock"
        first = FileLock(path)
        first.acquire()
        second = FileLock(path)
        try:
            with pytest.raises(LockContentionError):
                second.acquire()
        finally:
            first.release()


def test_second_acquire_allowed_after_release():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "log.lock"
        first = FileLock(path)
        first.acquire()
        first.release()
        second = FileLock(path)
        second.acquire()
        try:
            assert second.is_held()
        finally:
            second.release()


def test_acquire_twice_on_same_instance_raises():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "log.lock"
        lock = FileLock(path)
        lock.acquire()
        try:
            with pytest.raises(RuntimeError):
                lock.acquire()
        finally:
            lock.release()


def test_release_without_acquire_is_noop():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "log.lock"
        FileLock(path).release()  # should not raise


def test_info_on_absent_file_returns_empty():
    with tempfile.TemporaryDirectory() as tmp:
        info = FileLock(Path(tmp) / "nothing.lock").info()
        assert info.pid is None
        assert info.acquired_ts_ns is None
        assert info.raw == ""


def test_contention_error_names_holding_pid():
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "log.lock"
        held = FileLock(path)
        held.acquire()
        try:
            try:
                FileLock(path).acquire()
            except LockContentionError as e:
                assert str(os.getpid()) in str(e)
                return
            raise AssertionError("contention did not raise")
        finally:
            held.release()


def test_thread_cannot_defeat_file_lock():
    """Thread-based contention on the OS file lock — the second acquire
    must raise, even though threads share the process."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "log.lock"
        first = FileLock(path)
        first.acquire()
        result = {"err": None}

        def try_acquire():
            try:
                lock = FileLock(path)
                lock.acquire()
                lock.release()
            except Exception as e:
                result["err"] = e

        t = threading.Thread(target=try_acquire)
        t.start()
        t.join(timeout=2.0)
        first.release()
        assert isinstance(result["err"], LockContentionError), result
