"""SK-PRECEDENT-MATCH — find prior ADRs similar to a proposed change.

Distribution Spec §1.1 names precedent-match as a baseline skill. This
implementation ranks existing ADRs by TF-IDF cosine similarity against
a query string (the proposed change summary), so an author can see
what past decisions might be relevant before authoring a new ADR.

Stdlib-only TF-IDF: ~40 lines, zero new dependencies. Good enough for
the "surface 3 plausibly-related ADRs" use case. M4 may swap for an
embedding-backed ranker if the corpus grows.

Input schema:
  {root: str, query: str, top_k?: int, min_score?: number}

Output schema:
  {matches: [{adr_id, score, snippet}], total_adrs: int}
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

from aios.project.readers import read_adrs
from aios.skills.base import SkillContract, default_skill_registry

SKILL_ID = "SK-PRECEDENT-MATCH"

_TOKEN_RE = re.compile(r"[a-z0-9]+")


_INPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "root": {"type": "string", "minLength": 1},
        "query": {"type": "string", "minLength": 1},
        "top_k": {"type": "integer", "minimum": 1, "default": 3},
        "min_score": {"type": "number", "minimum": 0, "default": 0.1},
    },
    "required": ["root", "query"],
    "additionalProperties": False,
}

_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "total_adrs": {"type": "integer", "minimum": 0},
        "matches": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "adr_id": {"type": "string"},
                    "score": {"type": "number", "minimum": 0},
                    "snippet": {"type": "string"},
                },
                "required": ["adr_id", "score", "snippet"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["total_adrs", "matches"],
    "additionalProperties": False,
}


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def _read_adr_text(root: Path, adr_id: str) -> str:
    """Return the full body text of the ADR with this id, stripped of
    front matter. Best-effort — returns '' if we cannot locate the file."""
    for candidate_dir in ("adrs", "docs/adr", "doc/adr", "docs/adrs"):
        d = root / candidate_dir
        if not d.is_dir():
            continue
        for md in sorted(d.glob("*.md")):
            text = md.read_text(encoding="utf-8", errors="replace")
            if f"id: {adr_id}" in text:
                # strip front matter (everything between the first two `---`)
                if text.startswith("---\n"):
                    end = text.find("\n---", 4)
                    if end != -1:
                        body_start = end + len("\n---")
                        return text[body_start:].strip()
                return text
    return ""


def sk_precedent_match(inputs: dict) -> dict:
    root = Path(inputs["root"])
    query = inputs["query"]
    top_k = int(inputs.get("top_k", 3))
    min_score = float(inputs.get("min_score", 0.1))

    adrs = read_adrs(root)
    if not adrs:
        return {"total_adrs": 0, "matches": []}

    # Build the corpus: one document per ADR = front-matter statement +
    # body text. Use adr_id as a key.
    docs: dict[str, str] = {}
    for adr in adrs:
        body = _read_adr_text(root, adr.adr_id)
        docs[adr.adr_id] = f"{adr.adr_id} {body}"

    # Tokenize the corpus and the query.
    corpus_tokens = {k: _tokenize(v) for k, v in docs.items()}
    query_tokens = _tokenize(query)

    # Document frequency for IDF.
    doc_count = len(corpus_tokens) or 1
    df: Counter[str] = Counter()
    for tokens in corpus_tokens.values():
        df.update(set(tokens))

    def idf(term: str) -> float:
        # +1 smoothing in numerator and denominator to avoid div-by-zero
        # when a query term is absent from the corpus.
        return math.log((doc_count + 1) / (df[term] + 1)) + 1.0

    def tfidf(tokens: list[str]) -> dict[str, float]:
        if not tokens:
            return {}
        tf = Counter(tokens)
        total = sum(tf.values())
        return {t: (tf[t] / total) * idf(t) for t in tf}

    query_vec = tfidf(query_tokens)
    if not query_vec:
        return {"total_adrs": doc_count, "matches": []}

    def cosine(v1: dict[str, float], v2: dict[str, float]) -> float:
        if not v1 or not v2:
            return 0.0
        dot = sum(v1.get(t, 0.0) * v2.get(t, 0.0) for t in v1)
        n1 = math.sqrt(sum(w * w for w in v1.values()))
        n2 = math.sqrt(sum(w * w for w in v2.values()))
        if n1 == 0 or n2 == 0:
            return 0.0
        return dot / (n1 * n2)

    ranked: list[tuple[str, float]] = []
    for adr_id, tokens in corpus_tokens.items():
        score = cosine(query_vec, tfidf(tokens))
        if score >= min_score:
            ranked.append((adr_id, score))

    ranked.sort(key=lambda x: x[1], reverse=True)
    ranked = ranked[:top_k]

    matches = []
    for adr_id, score in ranked:
        body = docs[adr_id]
        snippet = body.strip().replace("\n", " ")[:200]
        matches.append({
            "adr_id": adr_id,
            "score": round(float(score), 6),
            "snippet": snippet,
        })

    return {"total_adrs": doc_count, "matches": matches}


_CONTRACT = SkillContract(
    id=SKILL_ID,
    version="1.0.0",
    owner_authority="A2",
    description="Rank prior ADRs by TF-IDF cosine similarity to a query "
                "(proposed change summary). Stdlib-only.",
    input_schema=_INPUT_SCHEMA,
    output_schema=_OUTPUT_SCHEMA,
    implementation=sk_precedent_match,
)


default_skill_registry.register(_CONTRACT)
