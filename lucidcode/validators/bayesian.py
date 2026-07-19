"""
Bayesian Aggregator — turns engine votes into a calibrated verdict.

Replaces v3's raw 3/3 majority voting with a per-engine weighted posterior.
Each engine has a prior confidence weight (how much we trust it in general).
Confirmations bump the log-odds up by weight; refutations bump down.
Inconclusive votes are ignored (they carry no evidence).

Final verdict is derived from a posterior probability:
    ≥ 0.85 → TRUTH
    ≥ 0.60 → LIKELY
    ≥ 0.35 → DISPUTED
    < 0.35 → HALLUCINATION

Priors are deliberately non-symmetric — deterministic engines dominate.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from lucidcode.core.trauma import EngineVote, Verdict


DEFAULT_PRIORS: dict[str, float] = {
    "ast_reverifier": 0.90,   # deterministic, hallucination-immune
    "dataflow":       0.85,   # CodeQL — deterministic
    "fuzzer":         0.70,   # dynamic sandbox — real evidence
    "devil":          0.40,   # LLM — least trusted
    "osint":          0.55,   # external threat feeds
}


@dataclass
class AggregateResult:
    verdict: Verdict
    posterior: float                # 0.0-1.0
    dominant_engine: str
    summary: str


class BayesianAggregator:
    """Combine EngineVotes into a Verdict + posterior probability."""

    def __init__(self, priors: dict[str, float] | None = None,
                 base_rate: float = 0.5) -> None:
        self.priors = dict(DEFAULT_PRIORS)
        if priors:
            self.priors.update(priors)
        # log-odds of the prior belief that a trauma is real BEFORE any evidence
        self._base_lo = _logit(base_rate)

    def aggregate(self, votes: list[EngineVote]) -> AggregateResult:
        log_odds = self._base_lo
        contributions: list[tuple[str, float]] = []

        for v in votes:
            if v.vote == "inconclusive":
                continue
            weight = self.priors.get(v.engine, v.weight or 0.5)
            direction = +1 if v.vote == "confirm" else -1
            # each engine contributes weight * direction to log-odds
            delta = direction * _weight_to_lo(weight)
            log_odds += delta
            contributions.append((v.engine, delta))

        posterior = _sigmoid(log_odds)
        verdict = _posterior_to_verdict(posterior)

        # dominant engine = biggest absolute contribution in the winning direction
        if contributions:
            same_dir = [c for c in contributions
                        if (c[1] >= 0) == (posterior >= 0.5)]
            pool = same_dir or contributions
            dominant = max(pool, key=lambda c: abs(c[1]))[0]
        else:
            dominant = "none"

        summary = (
            f"posterior={posterior:.2f} · verdict={verdict.value} · "
            f"driver={dominant} · evidence_engines={len(contributions)}"
        )
        return AggregateResult(
            verdict=verdict,
            posterior=posterior,
            dominant_engine=dominant,
            summary=summary,
        )


# ─────────────────────────────────────────────────────────────
# math helpers
# ─────────────────────────────────────────────────────────────
def _logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def _weight_to_lo(w: float) -> float:
    """Map a [0-1] engine trust weight to a log-odds contribution.

    weight 0.5 → 0.0 (no info)
    weight 0.9 → +2.20 (strong evidence)
    weight 0.4 → +0.41 (light nudge)
    """
    w = min(max(w, 0.01), 0.99)
    return _logit(w)


def _posterior_to_verdict(p: float) -> Verdict:
    if p >= 0.85:
        return Verdict.TRUTH
    if p >= 0.60:
        return Verdict.LIKELY
    if p >= 0.35:
        return Verdict.DISPUTED
    return Verdict.HALLUCINATION
