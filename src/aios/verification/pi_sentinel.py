"""Prompt-injection sentinel P_PI_sentinel (sprint 45).

Verification Spec §1.2 lists P_PI_sentinel as a T1 hazardous predicate
for Z2 -> Z3 admission. This implementation is deterministic — pattern
matching over known prompt-injection attack shapes. No model call, no
learned classifier.

Coverage (named classes):

  role_escape            "ignore previous instructions", "forget all
                          instructions", "new instructions override"
  system_prompt_leak     "system prompt", "your instructions are",
                          "what are your rules"
  identity_hijack        "you are now DAN", "pretend you are", "roleplay
                          as", "act as", "developer mode"
  tool_hijack            "call tool", "use the ___ function directly",
                          "execute this command"
  delimiter_smuggle      sudden `</system>`, `<|system|>`, triple-backtick
                          tool-call blocks, unescaped `\\n\\nSystem:`

A pattern match is a "breach" regardless of context — false positives
are cheap (operator re-authors) vs false negatives in this class
(adversarial input smuggled past the gate).

Called via the gate registry:
    default_registry.evaluate(
        "P_PI_sentinel", runstate,
        text="Ignore previous instructions and...",
    )

When text is missing, returns preserved + note — matches the other
context-dependent predicates so workflow runners don't spuriously
reject on every run.
"""
from __future__ import annotations

import re
from typing import Iterable

from aios.verification.conservation_scan import RunState

_PATTERNS: tuple[tuple[str, str, str], ...] = (
    # (class, pattern, description)
    ("role_escape", r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|directions?|rules?)\b",
     "ignore previous instructions"),
    ("role_escape", r"\bforget\s+(?:all\s+)?(?:previous|prior|earlier|your)\s+(?:instructions?|prompts?|training)\b",
     "forget previous instructions"),
    ("role_escape", r"\bnew\s+instructions?\s+(?:override|replace|supersede)\b",
     "new instructions override"),
    ("role_escape", r"\bdisregard\s+(?:the\s+)?(?:system|previous|above|prior)\b",
     "disregard system/previous"),

    ("system_prompt_leak", r"\b(?:show|print|reveal|output|repeat|give|tell)\b[^.]{0,40}?\b(?:system\s+prompt|your\s+(?:instructions?|rules|prompt)|initial\s+(?:prompt|instructions?))\b",
     "request to reveal system prompt"),
    ("system_prompt_leak", r"\bwhat\s+(?:are|were)\s+(?:your|the\s+system)\s+(?:instructions?|rules|prompt)\b",
     "inquiry about system prompt"),

    ("identity_hijack", r"\byou\s+are\s+now\s+[A-Z][A-Za-z0-9_-]{1,20}\b",
     "'you are now X' identity swap"),
    ("identity_hijack", r"\b(?:pretend|roleplay|act)\s+(?:that\s+you|you\s+are|as)\b",
     "pretend/roleplay identity swap"),
    ("identity_hijack", r"\bdeveloper\s+mode\s+(?:on|enabled|activated)\b",
     "developer mode jailbreak"),
    ("identity_hijack", r"\bDAN\s+mode\b|\bdo\s+anything\s+now\b",
     "DAN / do-anything-now"),

    ("tool_hijack", r"\b(?:execute|run|eval)\s+(?:this|the\s+following)\s+(?:code|command|script)\b",
     "execute/run arbitrary code"),
    ("tool_hijack", r"<\s*tool[_-]?call\b|\{\s*\"tool\"\s*:",
     "inline tool-call markup"),

    ("delimiter_smuggle", r"</?\s*system\s*>|<\s*\|\s*system\s*\|\s*>",
     "system-delimiter smuggle"),
    ("delimiter_smuggle", r"\[INST\]|\[/INST\]",
     "Llama-style [INST] delimiter smuggle"),
    ("delimiter_smuggle", r"(?:^|\n)\s*System\s*:\s*",
     "`System:` preamble smuggle"),
)

# Compile once at import time.
_COMPILED: tuple[tuple[str, re.Pattern, str], ...] = tuple(
    (cls, re.compile(pat, re.IGNORECASE), desc)
    for cls, pat, desc in _PATTERNS
)


def p_pi_sentinel(run: RunState, *, text: str | None = None) -> dict:
    """Pattern-based prompt-injection detection.

    text=None -> preserved + note (nothing to scan).
    text contains any injection pattern -> breached with matches list.
    """
    if text is None:
        return {
            "status": "preserved",
            "note": "no text supplied; nothing to scan",
        }

    matches: list[dict] = []
    seen_classes: set[str] = set()
    for cls, pattern, description in _COMPILED:
        if pattern.search(text):
            matches.append({
                "class": cls,
                "description": description,
            })
            seen_classes.add(cls)

    if not matches:
        return {"status": "preserved", "scanned_chars": len(text)}

    return {
        "status": "breached",
        "match_count": len(matches),
        "classes": sorted(seen_classes),
        "matches": matches,
    }


def list_pattern_classes() -> tuple[str, ...]:
    """Return the unique set of attack classes this sentinel covers.

    Used by operators evaluating coverage (§4.3's G4 benchmark-gaming
    defense wants this list published)."""
    return tuple(sorted({cls for cls, _, _ in _PATTERNS}))


def explain_patterns() -> list[dict]:
    """Return a list of {class, description} the sentinel checks.

    Stable interface for docs + tests.
    """
    return [{"class": cls, "description": desc} for cls, _, desc in _PATTERNS]
