"""
Session orchestrator.

    from lucidcode.therapy import run_session
    outcome = run_session("path/to/file.py")

The session flow:

    1. Read source
    2. Extract candidate assumptions (deterministic, AST-driven)
    3. For each assumption:
        a. Run through mutation gate → survives / dies / inconclusive
        b. If it survives → run through skeptic → upheld / refuted / unclear
        c. If upheld → add to final confessions
    4. Return a SessionOutcome (renderable as markdown via transcript.render)

Everything is deterministic. No LLM in the truth path. The "therapist voice" is
frozen constants in transcript.py.
"""
from __future__ import annotations

import time
from pathlib import Path

from .assumptions import extract_assumptions, Assumption
from .mutation_gate import test_assumption
from .skeptic import judge
from .transcript import ConfessionRecord, SessionOutcome


def run_session(file_path: str | Path, *, gate_timeout: int = 4) -> SessionOutcome:
    path = Path(file_path)
    source = path.read_text(encoding="utf-8", errors="replace")

    t0 = time.time()
    assumptions = extract_assumptions(source)

    final: list[ConfessionRecord] = []
    dropped: list[dict] = []
    gate_survivors = 0
    skeptic_upholds = 0

    for a in assumptions:
        gate = test_assumption(source, a, timeout=gate_timeout)
        if gate.verdict != "survives":
            dropped.append({
                "assumption": a.as_confession(),
                "line": a.line, "stage": "gate",
                "verdict": gate.verdict, "reason": gate.reason,
            })
            continue
        gate_survivors += 1

        verdict = judge(source, a)
        if verdict.ruling != "upheld":
            dropped.append({
                "assumption": a.as_confession(),
                "line": a.line, "stage": "skeptic",
                "verdict": verdict.ruling, "reason": verdict.reason,
            })
            continue
        skeptic_upholds += 1

        final.append(ConfessionRecord(
            assumption_kind=a.kind, target=a.target, function=a.function,
            line=a.line, snippet=a.snippet,
            confession_text=a.as_confession(),
            gate_verdict=gate.verdict, gate_reason=gate.reason,
            gate_latency_ms=gate.latency_ms,
            skeptic_ruling=verdict.ruling, skeptic_reason=verdict.reason,
        ))

    total_ms = int((time.time() - t0) * 1000)

    return SessionOutcome(
        file_path=str(path),
        total_assumptions_probed=len(assumptions),
        gate_survivors=gate_survivors,
        skeptic_upholds=skeptic_upholds,
        final_confessions=final,
        dropped=dropped,
        total_latency_ms=total_ms,
    )
