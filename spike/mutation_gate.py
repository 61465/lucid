"""
LucidCode — Mutation Gate SPIKE (throwaway)
============================================

The single question this file answers:

    Given (source, assumption_in_english), can we produce a clean survive/die
    verdict CHEAPLY?

If yes → the therapy paradigm has ground to stand on.
If no  → therapy is theater; kill the paradigm today.

An assumption is a structured record, NOT free text:

    Assumption(
        kind    = "not_zero" | "not_none" | "network_reachable" | "type_is",
        target  = "b" | "user" | "url",
        function= "divide",
        source  = "<verbatim source code>",
    )

The gate:
    1. Parses source, locates the target function.
    2. Synthesizes an adversarial call that violates the assumption.
    3. Runs {source + call} in the existing subprocess sandbox.
    4. Reads verdict from execution outcome:
         - exception raised    → survives (assumption was load-bearing, unprotected)
         - clean return / SAFE → dies    (assumption was guarded)
         - timeout             → survives (infinite-loop = load-bearing)
         - other               → inconclusive

NO LLM in this file. Pure mechanical mutation + execution. This is the ground.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

# reuse the sandbox we already built for v4
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lucidcode.sandbox import run_sandboxed  # noqa: E402


AssumptionKind = Literal[
    "not_zero",           # target arg is never zero
    "not_none",           # target arg is never None
    "not_empty",          # target arg is never empty ("" or [])
    "network_reachable",  # network call always succeeds
    "file_exists",        # file argument always exists on disk
]

Verdict = Literal["survives", "dies", "inconclusive"]


@dataclass
class Assumption:
    kind: AssumptionKind
    target: str            # arg name in the function signature
    function: str          # function name in the source

    def as_confession(self) -> str:
        m = {
            "not_zero":          f"I assumed `{self.target}` is never zero.",
            "not_none":          f"I assumed `{self.target}` is never None.",
            "not_empty":         f"I assumed `{self.target}` is never empty.",
            "network_reachable": f"I assumed the network call to `{self.target}` always succeeds.",
            "file_exists":       f"I assumed the path `{self.target}` always exists.",
        }
        return m[self.kind]


@dataclass
class GateResult:
    verdict: Verdict
    reason: str
    stdout: str = ""
    stderr: str = ""

    @property
    def confession_confirmed(self) -> bool:
        """The confession is REAL only when the negation actually broke things."""
        return self.verdict == "survives"


# ─────────────────────────────────────────────────────────────
# adversarial-input synthesis (per assumption kind)
# ─────────────────────────────────────────────────────────────
def _adversarial_args(kind: AssumptionKind, target: str,
                      arg_positions: list[str]) -> str:
    """Build a positional-args string that violates the assumption.

    All other args get a benign default (1 for numerics, "x" for strings).
    """
    parts = []
    for name in arg_positions:
        if name == target:
            if kind == "not_zero":
                parts.append("0")
            elif kind == "not_none":
                parts.append("None")
            elif kind == "not_empty":
                parts.append('""')
            elif kind == "network_reachable":
                parts.append('"http://127.0.0.1:1"')  # closed port
            elif kind == "file_exists":
                parts.append('"/nonexistent/lucid/path/xyz"')
        else:
            parts.append("1")   # boring default
    return ", ".join(parts)


def _extract_arg_names(source: str, function_name: str) -> list[str]:
    """Pull positional arg names from `def function_name(...)`."""
    import ast
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            return [a.arg for a in node.args.args]
    return []


# ─────────────────────────────────────────────────────────────
# THE GATE
# ─────────────────────────────────────────────────────────────
def test_assumption(source: str, assumption: Assumption, timeout: int = 3) -> GateResult:
    args = _extract_arg_names(source, assumption.function)
    if not args:
        return GateResult(
            verdict="inconclusive",
            reason=f"function `{assumption.function}` not found in source",
        )
    if assumption.target not in args:
        return GateResult(
            verdict="inconclusive",
            reason=f"target `{assumption.target}` not in args {args}",
        )

    adversarial_call = _adversarial_args(assumption.kind, assumption.target, args)
    harness = source + (
        f"\n\n"
        f"try:\n"
        f"    _r = {assumption.function}({adversarial_call})\n"
        f"    print('SAFE:', repr(_r)[:60])\n"
        f"except Exception as _e:\n"
        f"    print('VULN_TRIGGERED:', type(_e).__name__, str(_e)[:60])\n"
    )

    result = run_sandboxed(harness, timeout=timeout, mode="subprocess")

    if result.verdict == "vuln_triggered":
        return GateResult(
            verdict="survives",
            reason=f"adversarial input broke `{assumption.function}` — confession is real",
            stdout=result.stdout, stderr=result.stderr,
        )
    if result.verdict == "safe":
        return GateResult(
            verdict="dies",
            reason=f"adversarial input handled cleanly — assumption was guarded",
            stdout=result.stdout, stderr=result.stderr,
        )
    if result.verdict == "timeout":
        return GateResult(
            verdict="survives",
            reason="adversarial input caused a hang — assumption was load-bearing",
            stdout=result.stdout, stderr=result.stderr,
        )
    return GateResult(
        verdict="inconclusive",
        reason=f"sandbox verdict={result.verdict}: {result.detail[:80]}",
        stdout=result.stdout, stderr=result.stderr,
    )


# ─────────────────────────────────────────────────────────────
# THE THREE-CASE PROOF (day-one verdict)
# ─────────────────────────────────────────────────────────────
CASES = [
    {
        "name":       "A · unguarded divide (should SURVIVE)",
        "source":     "def divide(a, b):\n    return a / b\n",
        "assumption": Assumption(kind="not_zero", target="b", function="divide"),
        "expected":   "survives",
    },
    {
        "name":       "B · guarded divide (should DIE)",
        "source":     "def divide(a, b):\n    return a / b if b else 0\n",
        "assumption": Assumption(kind="not_zero", target="b", function="divide"),
        "expected":   "dies",
    },
    {
        "name":       "C · unguarded network call (should SURVIVE)",
        "source":     "import urllib.request\ndef fetch(url):\n    return urllib.request.urlopen(url).status\n",
        "assumption": Assumption(kind="network_reachable", target="url", function="fetch"),
        "expected":   "survives",
    },
]


def run_proof() -> int:
    print("LucidCode Mutation-Gate spike — day-one proof")
    print("=" * 60)
    all_ok = True
    import time
    for case in CASES:
        t0 = time.time()
        result = test_assumption(case["source"], case["assumption"])
        elapsed = int((time.time() - t0) * 1000)
        ok = result.verdict == case["expected"]
        all_ok &= ok
        mark = "PASS" if ok else "FAIL"
        conf = case["assumption"].as_confession()
        print(f"[{mark}] {case['name']}")
        print(f"       confession       : {conf}")
        print(f"       expected verdict : {case['expected']}")
        print(f"       actual verdict   : {result.verdict}   ({elapsed}ms)")
        print(f"       reason           : {result.reason}")
        if not ok:
            print(f"       stdout           : {result.stdout[:120]}")
            print(f"       stderr           : {result.stderr[:120]}")
        print()
    print("=" * 60)
    if all_ok:
        print("VERDICT: THE JEWEL EXISTS. Build therapy on top of this gate.")
        return 0
    print("VERDICT: The jewel does not exist as designed. Redesign or kill.")
    return 1


if __name__ == "__main__":
    sys.exit(run_proof())
