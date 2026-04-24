"""AIOS — v8 P-Local reference implementation.

Five-doc spec stack (vendored in docs/spec/):
  Constitution v1.0, Kernel v1.0, Distribution v1.0,
  Verification v1.0, Runtime Protocol v1.0.

Scope of this package: the P-Local conformance profile per Runtime
Protocol §10.1. Explicit not-implemented list in docs/coverage.md.
"""
from __future__ import annotations

__version__ = "0.2.0"
__spec_versions__ = {
    "constitution": "1.0.0",
    "kernel": "1.0.0",
    "distribution": "1.0.0",
    "verification": "1.0.0",
    "runtime_protocol": "1.0.0",
}
