"""Runtime subsystem: event log, profile, init.

See docs/spec/AIOS_Runtime_Protocol.md and AIOS_Kernel_Spec.md.
"""
from __future__ import annotations

from aios.runtime.event_log import (
    EventLog,
    Frame,
    cbor_encode,
    sha256,
    crc32c,
    HEADER_TOTAL_SIZE,
)

__all__ = [
    "EventLog",
    "Frame",
    "cbor_encode",
    "sha256",
    "crc32c",
    "HEADER_TOTAL_SIZE",
]
