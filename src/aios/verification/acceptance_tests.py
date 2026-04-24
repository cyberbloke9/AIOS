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

import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable

from aios.verification.conservation_scan import RunState

# Env variables that are always scrubbed under sandbox=True. Matches
# common secret-naming patterns across ecosystems (AWS, GCP, Azure,
# GitHub, Slack, etc.). The list is checked case-insensitively as a
# SUFFIX match so XYZ_API_KEY, MY_SECRET, PRIVATE_KEY etc. all go.
_SECRET_SUFFIXES = (
    "_TOKEN", "_KEY", "_SECRET", "_PASSWORD", "_PASSWD",
    "_API_KEY", "_ACCESS_KEY", "_PRIVATE_KEY", "_CREDENTIAL",
)
_SECRET_EXACT = (
    "DATABASE_URL", "AWS_SESSION_TOKEN", "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN", "SLACK_TOKEN", "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
)


def scrub_env(env: dict[str, str]) -> dict[str, str]:
    """Remove secret-looking variables from an env dict.

    Not foolproof (malicious test code can still exfiltrate any env
    variable it sees) but removes the obvious low-hanging secrets.
    Callers that need stricter isolation should run pytest under
    a container or separate OS user.
    """
    kept: dict[str, str] = {}
    for k, v in env.items():
        ku = k.upper()
        if ku in _SECRET_EXACT:
            continue
        if any(ku.endswith(sfx) for sfx in _SECRET_SUFFIXES):
            continue
        kept[k] = v
    return kept


def _build_preexec_fn(memory_limit_mb: int | None):
    """POSIX resource.setrlimit preexec_fn — None on Windows."""
    if os.name == "nt" or memory_limit_mb is None:
        return None
    try:
        import resource
    except ImportError:
        return None

    bytes_limit = int(memory_limit_mb * 1024 * 1024)

    def preexec():
        # RLIMIT_AS = total address space. Tighter than RSS but portable.
        try:
            resource.setrlimit(resource.RLIMIT_AS,
                               (bytes_limit, bytes_limit))
        except (ValueError, OSError):
            pass
    return preexec

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
    sandbox: bool = False,
    memory_limit_mb: int | None = None,
) -> dict:
    """Run pytest on suite_path and return the §1.2 T2 verdict dict.

    `sandbox=True` enables env scrubbing (strips *_TOKEN / *_KEY /
    *_SECRET / *_PASSWORD vars + a small allow-list of known secret
    names like DATABASE_URL, AWS_SESSION_TOKEN). POSIX further gets
    resource.setrlimit(RLIMIT_AS) applied via preexec_fn when
    memory_limit_mb is supplied. Windows ignores memory_limit_mb
    (native sandboxing via Job Objects is deferred) but still scrubs
    env. Callers wanting stricter isolation should run pytest under
    a container or separate OS user — this sandbox raises the bar,
    it is not a full containment boundary.
    """
    if suite_path is None:
        return {
            "status": "preserved",
            "note": "no suite_path supplied; nothing to run",
        }

    args = list(pytest_args) if pytest_args else ["--tb=no", "-q"]
    python = python_executable or sys.executable

    cmd = [python, "-m", "pytest", str(suite_path), *args]

    run_kwargs: dict = {
        "capture_output": True,
        "text": True,
        "timeout": timeout_seconds,
    }
    if sandbox:
        run_kwargs["env"] = scrub_env(dict(os.environ))
        preexec = _build_preexec_fn(memory_limit_mb)
        if preexec is not None:
            run_kwargs["preexec_fn"] = preexec

    started = time.monotonic()
    try:
        result = subprocess.run(cmd, **run_kwargs)
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
        "sandbox": sandbox,
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
