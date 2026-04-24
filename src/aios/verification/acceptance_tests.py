"""P_acceptance_tests — pytest wrapper predicate (sprint 46).

Verification Spec §1.2 lists P_acceptance_tests as a T2 stochastic_bounded
gate used for workflow acceptance checks. This implementation shells out
to pytest as a subprocess, captures the test result, and reports the
counts + duration. The "breach" verdict fires on any test failure.

Usage via the registry:
    default_registry.evaluate(
        "P_acceptance_tests", runstate,
        suite_path="tests/",
        pytest_args=["-q", "--tb=short"],
        timeout_seconds=600.0,
    )

    suite_path      path the subprocess will run pytest against. Can be
                    a directory, a file, or a nodeid (tests/test_x.py::t).
    pytest_args     extra arguments to forward. Useful for -k filters,
                    marker selection, or coverage. Defaults to a minimal
                    ["--tb=no", "-q"].
    timeout_seconds upper bound on pytest execution. Exceeding fires
                    "breached" with status_reason="timeout".

Safety: this runs arbitrary test code, which can execute arbitrary
commands. In production deployments, run under an isolation boundary
(container, firejail, or separate OS user). v0.4.0 does not provide
sandboxing — that is M5's deployment story.
"""
from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

from aios.verification.conservation_scan import RunState

# Pytest exit codes (see pytest docs):
#   0  all tests passed
#   1  tests were collected and run but some failed
#   2  test execution was interrupted by the user
#   3  internal error happened while executing tests
#   4  pytest command line usage error
#   5  no tests were collected

_SUMMARY_PATTERN = re.compile(
    r"(?P<count>\d+)\s+(?P<name>passed|failed|skipped|error|errors|xfailed|xpassed|deselected|warning|warnings)",
    re.IGNORECASE,
)


def p_acceptance_tests(
    run: RunState,
    *,
    suite_path: str | Path | None = None,
    pytest_args: Iterable[str] | None = None,
    timeout_seconds: float = 600.0,
    python_executable: str | None = None,
) -> dict:
    """Run pytest on suite_path and return the §1.2 T2 verdict dict."""
    if suite_path is None:
        return {
            "status": "preserved",
            "note": "no suite_path supplied; nothing to run",
        }

    args = list(pytest_args) if pytest_args else ["--tb=no", "-q"]
    python = python_executable or sys.executable

    cmd = [python, "-m", "pytest", str(suite_path), *args]

    started = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
        return {
            "status": "breached",
            "status_reason": "timeout",
            "duration_seconds": round(elapsed, 3),
            "timeout_seconds": timeout_seconds,
            "command": cmd,
        }
    except FileNotFoundError as e:
        return {
            "status": "breached",
            "status_reason": "pytest_not_available",
            "error": str(e),
            "command": cmd,
        }

    elapsed = time.monotonic() - started
    counts = _parse_summary(result.stdout + "\n" + result.stderr)

    # Pytest exit codes drive the status decision:
    if result.returncode == 0:
        status = "preserved"
        reason = None
    elif result.returncode == 1:
        status = "breached"
        reason = "tests_failed"
    elif result.returncode == 5:
        # No tests collected — treat as preserved + warning; §1.2 says
        # acceptance tests have stochastic_bounded semantics, so running
        # zero tests is not itself a breach.
        status = "preserved"
        reason = "no_tests_collected"
    elif result.returncode == 4:
        status = "breached"
        reason = "pytest_usage_error"
    elif result.returncode == 2:
        status = "breached"
        reason = "interrupted"
    else:
        status = "breached"
        reason = f"pytest_internal_error_rc={result.returncode}"

    out = {
        "status": status,
        "exit_code": result.returncode,
        "duration_seconds": round(elapsed, 3),
        "passed": counts.get("passed", 0),
        "failed": counts.get("failed", 0),
        "errors": counts.get("errors", 0) + counts.get("error", 0),
        "skipped": counts.get("skipped", 0),
        "xfailed": counts.get("xfailed", 0),
        "xpassed": counts.get("xpassed", 0),
        "command": cmd,
    }
    if reason is not None:
        out["status_reason"] = reason
    return out


def _parse_summary(text: str) -> dict[str, int]:
    """Best-effort extraction of {name: count} from pytest output.

    Looks for patterns like '142 passed, 3 failed in 4.56s' anywhere in
    the captured stdout/stderr. Missing categories default to 0 at the
    call site.
    """
    counts: dict[str, int] = {}
    for m in _SUMMARY_PATTERN.finditer(text):
        name = m.group("name").lower().rstrip("s")   # normalize plural
        if name == "warning":
            name = "warnings"
        counts[name] = int(m.group("count"))
    return counts
