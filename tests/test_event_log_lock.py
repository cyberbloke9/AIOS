"""Tests for EventLog writer-lock integration (sprint 14)."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from aios.runtime.event_log import EventLog
from aios.runtime.filelock import LockContentionError


def test_second_eventlog_on_open_log_refused():
    with tempfile.TemporaryDirectory() as tmp:
        first = EventLog(tmp)
        try:
            with pytest.raises(LockContentionError):
                EventLog(tmp)
        finally:
            first.close()


def test_second_eventlog_allowed_after_close():
    with tempfile.TemporaryDirectory() as tmp:
        first = EventLog(tmp)
        first.append(kind="x", actor="A1", payload={})
        first.close()

        # After close, second open succeeds
        second = EventLog(tmp)
        second.close()


def test_close_is_idempotent():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.close()
        log.close()  # must not raise


def test_lock_file_created_in_root():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        try:
            assert (Path(tmp) / "log.lock").exists()
        finally:
            log.close()


def test_lock_released_after_exception_during_init(tmp_path, monkeypatch):
    """If _recover_or_init raises, the lock must be released so the dir
    can be reopened after the caller fixes the problem."""
    # Put a corrupted segment file into the dir so _recover_or_init fails.
    bad_segment = tmp_path / "segment_0_999.aios"
    bad_segment.write_bytes(b"not a valid segment file")

    with pytest.raises(Exception):
        EventLog(tmp_path)

    # Remove the corruption and verify the lock is not still held
    bad_segment.unlink()
    log = EventLog(tmp_path)
    try:
        assert log is not None
    finally:
        log.close()


def test_init_aios_home_sequence_still_works():
    """init -> append -> close -> replay pattern still works with the
    lock in place, because init_aios_home closes its EventLog before
    returning (tested via the existing init tests)."""
    from aios.runtime.init import init_aios_home
    with tempfile.TemporaryDirectory() as tmp:
        init_aios_home(tmp)
        # A second caller can now open the events/ directory for append
        log = EventLog(Path(tmp) / "events")
        log.append(kind="post.init", actor="A1", payload={})
        log.close()
