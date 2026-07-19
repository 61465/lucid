"""
LucidCode Pipeline — the composed v4 flow.

    from lucidcode.pipeline import analyze
    result = analyze(source_code)

Order:
    1. Prompt Shield  — reject or sanitize input
    2. AST Surgeon    — detect all 12 syndromes
    3. Truth Validator — 3+ engines vote on each trauma
    4. Bayesian aggregator — posterior probability + verdict
    5. Return list[ValidatedTrauma], filtered to show TRUTH/LIKELY/DISPUTED.

HALLUCINATION verdicts are logged to a rejection ledger but never shown to
the user. This is the anti-hallucination guarantee LucidCode makes.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from .core.prompt_shield import sanitize_source
from .core.trauma import Trauma, ValidatedTrauma, Verdict
from .syndromes import detect_all
from .validators import validate_trauma
from .validators.base import Engine


REJECTION_LEDGER = Path(__file__).resolve().parent.parent / "logs" / "rejected_confessions.jsonl"


@dataclass
class AnalysisResult:
    ok: bool
    source_bytes: int
    shield_reason: str
    traumas_detected: int
    shown: list[ValidatedTrauma]
    rejected: list[ValidatedTrauma]
    latency_ms: int

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "source_bytes": self.source_bytes,
            "shield_reason": self.shield_reason,
            "traumas_detected": self.traumas_detected,
            "shown": [v.to_dict() for v in self.shown],
            "rejected_count": len(self.rejected),
            "latency_ms": self.latency_ms,
        }


def analyze(source: str, engines: list[Engine] | None = None,
            log_rejections: bool = True) -> AnalysisResult:
    t0 = time.time()

    # 1. shield
    shield = sanitize_source(source)
    if not shield.ok:
        return AnalysisResult(
            ok=False,
            source_bytes=len(source.encode("utf-8", "replace")),
            shield_reason=shield.reason,
            traumas_detected=0,
            shown=[],
            rejected=[],
            latency_ms=int((time.time() - t0) * 1000),
        )

    src = shield.sanitized

    # 2. AST Surgeon
    raw_hits = detect_all(src)

    # 3-4. Validator + aggregator
    shown: list[ValidatedTrauma] = []
    rejected: list[ValidatedTrauma] = []
    for h in raw_hits:
        trauma = Trauma(
            id=h["id"],
            syndrome=h["syndrome"],
            severity=h["severity"],
            line=h["line"],
            evidence=h["evidence"],
            confession=h["confession"],
            predicate=h.get("predicate", {}),
            adversary=h.get("adversary", ""),
        )
        v = validate_trauma(src, trauma, engines=engines)
        if v.verdict == Verdict.HALLUCINATION:
            rejected.append(v)
        else:
            shown.append(v)

    # 5. log rejections (only if we actually filtered any)
    if log_rejections and rejected:
        _log_rejections(rejected)

    return AnalysisResult(
        ok=True,
        source_bytes=len(source.encode("utf-8", "replace")),
        shield_reason="",
        traumas_detected=len(raw_hits),
        shown=shown,
        rejected=rejected,
        latency_ms=int((time.time() - t0) * 1000),
    )


def _log_rejections(rejected: list[ValidatedTrauma]) -> None:
    try:
        REJECTION_LEDGER.parent.mkdir(parents=True, exist_ok=True)
        with REJECTION_LEDGER.open("a", encoding="utf-8") as f:
            for v in rejected:
                f.write(json.dumps({
                    "ts": time.time(),
                    "trauma": v.trauma.to_dict(),
                    "votes": [x.to_dict() for x in v.votes],
                    "posterior": v.posterior_probability,
                }, ensure_ascii=False) + "\n")
    except Exception:
        # ledger failure must not break analysis
        pass


if __name__ == "__main__":
    import sys
    src = sys.stdin.read() if not sys.stdin.isatty() else (
        sys.argv[1] if len(sys.argv) > 1 else ""
    )
    if not src:
        print("Usage: echo <code> | python -m lucidcode.pipeline")
        sys.exit(1)

    result = analyze(src)
    print(f"# ok={result.ok} shield={result.shield_reason or 'clean'} "
          f"detected={result.traumas_detected} shown={len(result.shown)} "
          f"rejected={len(result.rejected)} latency={result.latency_ms}ms\n")
    for v in result.shown:
        t = v.trauma
        print(f"[{v.verdict.value:14s}] {t.syndrome:22s} line={t.line:3d} "
              f"posterior={v.posterior_probability:.2f} driver={v.dominant_evidence}")
        print(f"   confession: {t.confession[:100]}...")
