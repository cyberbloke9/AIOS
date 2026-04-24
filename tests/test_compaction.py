"""Tests for §1.7 compaction (sprint 49)."""
from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path

import pytest

from aios.cli import main
from aios.runtime.event_log import EventLog, HEADER_TOTAL_SIZE, _unpack_header


# ---------------------------------------------------------------------------
# Core compact() behavior
# ---------------------------------------------------------------------------


def test_compact_refuses_through_seq_beyond_head():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        with pytest.raises(ValueError, match="beyond current head"):
            log.compact(through_seq=999, projections={"p": {}})
        log.close()


def test_compact_refuses_negative_through_seq():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="x", actor="A1", payload={})
        with pytest.raises(ValueError, match=">= 0"):
            log.compact(through_seq=-1, projections={"p": {}})
        log.close()


def test_compact_appends_snapshot_frame_with_correct_as_of_seq():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        for i in range(5):
            log.append(kind="x", actor="A1", payload={"i": i})
        report = log.compact(through_seq=2, projections={"p": {"v": 2}})
        assert report["snapshot_seq"] == 5  # next seq after the 5 frames
        assert report["as_of_seq"] == 2

        # Verify the snapshot frame is there with the right payload
        log.close()
        log2 = EventLog(tmp)
        snap = log2.find_latest_snapshot()
        assert snap is not None
        assert snap.payload["as_of_seq"] == 2
        assert snap.payload.get("compaction") is True
        log2.close()


def test_compact_marks_closed_segments_up_to_through_seq():
    with tempfile.TemporaryDirectory() as tmp:
        # Force tight rotation so we have multiple closed segments
        log = EventLog(tmp, rotate_after_frames=2)
        for i in range(6):
            log.append(kind="x", actor="A1", payload={"i": i})
        # With rotate_after_frames=2, segments: [0..1], [2..3], [4..5], OPEN
        report = log.compact(through_seq=3, projections={"p": {"v": 1}})
        log.close()

        # Segments ending at <= 3: segment_0_1, segment_2_3
        marked = set(report["compacted_segments"])
        assert "segment_0_1.aios" in marked
        assert "segment_2_3.aios" in marked
        assert "segment_4_5.aios" not in marked   # ends at 5, > 3


def test_compact_sets_flag_bit_1_on_marked_segments():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, rotate_after_frames=2)
        for i in range(4):
            log.append(kind="x", actor="A1", payload={"i": i})
        report = log.compact(through_seq=1, projections={"p": {}})
        log.close()

        # Check the first segment's header has bit 1 (0x02) set
        segs = sorted(Path(tmp).glob("segment_*.aios"),
                      key=lambda p: int(p.name.split("_")[1]))
        first_closed = segs[0]
        hdr_raw = first_closed.read_bytes()[:HEADER_TOTAL_SIZE]
        hdr = _unpack_header(hdr_raw)
        assert hdr["flags"] & 0x02, "compacted flag bit 1 not set"


def test_compact_does_not_delete_source_segments():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, rotate_after_frames=2)
        for i in range(4):
            log.append(kind="x", actor="A1", payload={"i": i})
        log.compact(through_seq=1, projections={"p": {}})
        log.close()

        # All segments still on disk — §1.7 retention rule
        segs = list(Path(tmp).glob("segment_*.aios"))
        assert len(segs) >= 2


def test_compact_does_not_mutate_frame_bytes_in_closed_segments():
    """Compaction must touch only the header flags bit; frame bodies
    stay bit-identical (audit trail integrity)."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp, rotate_after_frames=2)
        for i in range(4):
            log.append(kind="x", actor="A1", payload={"i": i})
        log.close()

        # Snapshot the frame bytes of the first closed segment
        seg = sorted(Path(tmp).glob("segment_*.aios"),
                     key=lambda p: int(p.name.split("_")[1]))[0]
        before = seg.read_bytes()
        frames_bytes_before = before[HEADER_TOTAL_SIZE:]

        log2 = EventLog(tmp, rotate_after_frames=2)
        log2.compact(through_seq=1, projections={"p": {}})
        log2.close()

        after = seg.read_bytes()
        frames_bytes_after = after[HEADER_TOTAL_SIZE:]
        # Frame body identical
        assert frames_bytes_after == frames_bytes_before
        # Header bytes differ (flag bit flipped)
        assert after[:HEADER_TOTAL_SIZE] != before[:HEADER_TOTAL_SIZE]


def test_compact_snapshot_is_queryable_via_find_latest_snapshot():
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        for i in range(3):
            log.append(kind="x", actor="A1", payload={"i": i})
        log.compact(through_seq=1, projections={"p": {"state": "compacted"}})

        snap = log.find_latest_snapshot()
        log.close()
        assert snap is not None
        assert snap.payload["as_of_seq"] == 1
        assert snap.payload["compaction"] is True


def test_compact_state_loadable_via_snapshot_replay():
    """After compaction, a fresh reader can use the snapshot to skip
    replay of compacted frames and still arrive at the right state."""
    with tempfile.TemporaryDirectory() as tmp:
        log = EventLog(tmp)
        log.append(kind="inc", actor="A1", payload={})
        log.append(kind="inc", actor="A1", payload={})
        log.append(kind="inc", actor="A1", payload={})
        # Compact through seq=2 with pre-computed state (count=3)
        log.compact(through_seq=2, projections={"counter": {"count": 3}})
        log.append(kind="inc", actor="A1", payload={})      # post-compaction
        log.close()

        log2 = EventLog(tmp)
        snap = log2.find_latest_snapshot()
        state = log2.load_snapshot_state(snap)["counter"]
        # Apply only post-snapshot frames
        for f in log2.replay_from_snapshot(snap):
            if f.kind == "inc":
                state = {"count": state["count"] + 1}
        log2.close()
        assert state == {"count": 4}


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_cli_compact_happy_path(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    # Append a few frames beyond the genesis
    for i in range(3):
        main(["append", "--home", str(home),
              "--kind", "x", "--actor", "A1",
              "--payload", f'{{"i":{i}}}'])

    proj = tmp_path / "proj.json"
    proj.write_text(json.dumps({"counter": {"count": 3}}))
    capsys.readouterr()

    rc = main(["compact", "--through-seq", "3",
               "--projections", str(proj), "--home", str(home)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "compacted through seq=3" in out
    assert "snapshot appended at seq=" in out


def test_cli_compact_rejects_bad_projections(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    bad = tmp_path / "bad.json"
    bad.write_text("[1, 2, 3]")  # not a dict
    capsys.readouterr()
    rc = main(["compact", "--through-seq", "0",
               "--projections", str(bad), "--home", str(home)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "top-level object" in err


def test_cli_compact_rejects_beyond_head(tmp_path: Path, capsys):
    home = tmp_path / "h"
    main(["init", str(home)])
    proj = tmp_path / "p.json"
    proj.write_text(json.dumps({"x": {}}))
    capsys.readouterr()
    rc = main(["compact", "--through-seq", "999",
               "--projections", str(proj), "--home", str(home)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "refused" in err or "beyond" in err


def test_cli_compact_in_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "compact" in out
