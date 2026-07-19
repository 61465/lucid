"""
Truth Validator Orchestra — runs all engines in parallel + aggregates.

    from lucidcode.validators import validate_trauma
    result = validate_trauma(source, trauma, engines=[...])
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from lucidcode.core.trauma import Trauma, ValidatedTrauma
from .base import Engine
from .ast_reverifier import ASTReverifierEngine
from .fuzzer import FuzzerEngine
from .bayesian import BayesianAggregator


def default_engines() -> list[Engine]:
    """The default 3-engine ensemble that runs without any LLM key.

    Devil is opt-in — inject it via `engines=` when an LLM caller is available.
    """
    return [ASTReverifierEngine(), FuzzerEngine()]


def validate_trauma(source: str, trauma: Trauma,
                    engines: list[Engine] | None = None,
                    aggregator: BayesianAggregator | None = None) -> ValidatedTrauma:
    engines = engines or default_engines()
    aggregator = aggregator or BayesianAggregator()

    votes = []
    with ThreadPoolExecutor(max_workers=min(len(engines), 6)) as ex:
        futs = {ex.submit(e.to_engine_vote, source, trauma): e for e in engines}
        for f in as_completed(futs):
            votes.append(f.result())

    result = aggregator.aggregate(votes)
    return ValidatedTrauma(
        trauma=trauma,
        votes=votes,
        verdict=result.verdict,
        posterior_probability=result.posterior,
        dominant_evidence=result.dominant_engine,
        summary=result.summary,
    )
