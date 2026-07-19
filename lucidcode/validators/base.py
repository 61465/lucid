"""Validator base — every engine implements Engine.vote(trauma) -> EngineResult."""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from lucidcode.core.trauma import Trauma, EngineVote


@dataclass
class EngineResult:
    vote: str                    # "confirm" | "refute" | "inconclusive"
    reason: str = ""
    provider: str = ""
    latency_ms: int = 0
    meta: dict = field(default_factory=dict)


class Engine(ABC):
    """One anti-hallucination validator."""

    name: str = "unnamed"
    prior_weight: float = 0.5    # Bayesian prior confidence (0-1)

    @abstractmethod
    def vote(self, source: str, trauma: Trauma) -> EngineResult:
        """Return this engine's opinion on whether `trauma` is real."""
        ...

    def to_engine_vote(self, source: str, trauma: Trauma) -> EngineVote:
        """Time the call and wrap the result in an EngineVote."""
        t0 = time.time()
        try:
            r = self.vote(source, trauma)
        except Exception as e:
            r = EngineResult(vote="inconclusive", reason=f"engine error: {e}"[:200])
        latency = int((time.time() - t0) * 1000)
        return EngineVote(
            engine=self.name,
            vote=r.vote,
            reason=r.reason,
            weight=self.prior_weight,
            provider=r.provider,
            latency_ms=r.latency_ms or latency,
            meta=r.meta,
        )
