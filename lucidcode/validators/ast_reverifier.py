"""
AST Re-Verifier Engine — deterministic, hallucination-immune.

Re-runs the trauma's own AST predicate against the source. If the pattern
that triggered the syndrome is still present at the same line, we confirm.
No LLM involvement whatsoever — this is the "ground truth" engine.
"""
from __future__ import annotations

import ast

from lucidcode.core.trauma import Trauma
from lucidcode.syndromes import SYNDROMES
from .base import Engine, EngineResult


class ASTReverifierEngine(Engine):
    name = "ast_reverifier"
    prior_weight = 0.90    # highest — deterministic, cannot hallucinate

    def vote(self, source: str, trauma: Trauma) -> EngineResult:
        syndrome = SYNDROMES.get(trauma.syndrome)
        if not syndrome:
            return EngineResult(
                vote="inconclusive",
                reason=f"no registered syndrome named {trauma.syndrome}",
            )
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            return EngineResult(
                vote="inconclusive",
                reason=f"source unparseable: {e.msg}",
            )
        for hit in syndrome.detect(tree):
            if hit.get("line") == trauma.line:
                return EngineResult(
                    vote="confirm",
                    reason=f"syndrome predicate still matches at line {trauma.line}",
                    meta={"predicate": hit.get("predicate", {})},
                )
        return EngineResult(
            vote="refute",
            reason=f"no matching syndrome pattern at line {trauma.line} on re-scan",
        )
