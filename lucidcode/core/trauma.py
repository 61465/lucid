"""
Core dataclasses shared across LucidCode modules.

    Trauma           — one syndrome hit surfaced by the AST Surgeon.
    EngineVote       — one validator's opinion on a Trauma.
    ValidatedTrauma  — Trauma + all EngineVotes + final Verdict.
    Verdict          — enum of possible outcomes.

Kept deliberately dependency-free so validators/, sandbox/, ui/, exporters/
can all consume this without pulling heavy imports.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    TRUTH = "TRUTH"                # 3+ engines confirm
    LIKELY = "LIKELY"              # 2 engines confirm
    DISPUTED = "DISPUTED"          # 1 engine confirms
    HALLUCINATION = "HALLUCINATION" # 0 engines confirm


@dataclass
class Trauma:
    """One syndrome hit — the raw finding before validation."""
    id: str
    syndrome: str
    severity: str                  # CRITICAL / HIGH / MEDIUM / LOW
    line: int
    evidence: str                  # short human string
    confession: str                # first-person text (may be filled by LLM later)
    predicate: dict = field(default_factory=dict)  # for AST re-verifier
    adversary: str = ""            # hint used by Fuzzer to build test input
    file: str = "<inline>"
    lang: str = "python"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EngineVote:
    """One validator's opinion on one Trauma."""
    engine: str                    # "ast_reverifier" / "fuzzer" / "devil" / "dataflow"
    vote: str                      # "confirm" / "refute" / "inconclusive"
    reason: str = ""               # short explanation
    weight: float = 1.0            # prior confidence in this engine's opinion
    provider: str = ""             # LLM provider family (if applicable)
    latency_ms: int = 0
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ValidatedTrauma:
    """Trauma + all engine votes + final aggregated Verdict."""
    trauma: Trauma
    votes: list[EngineVote]
    verdict: Verdict
    posterior_probability: float   # 0.0-1.0 — Bayesian posterior
    dominant_evidence: str = ""    # which engine drove the verdict most
    summary: str = ""

    @property
    def is_shown(self) -> bool:
        """Whether UI should surface this trauma to the user."""
        return self.verdict in (Verdict.TRUTH, Verdict.LIKELY, Verdict.DISPUTED)

    def to_dict(self) -> dict:
        return {
            "trauma": self.trauma.to_dict(),
            "votes": [v.to_dict() for v in self.votes],
            "verdict": self.verdict.value,
            "posterior_probability": self.posterior_probability,
            "dominant_evidence": self.dominant_evidence,
            "summary": self.summary,
        }
