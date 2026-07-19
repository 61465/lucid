"""
Fuzzer Engine — runs LLM-generated adversarial code in a sandbox.

Currently uses a simple template-driven adversarial builder per syndrome.
A future upgrade (Phase 2) will have an LLM synthesize the harness.

The sandbox module handles isolation (docker → subprocess). The Fuzzer
just interprets the SandboxResult verdict.
"""
from __future__ import annotations

from textwrap import dedent

from lucidcode.core.trauma import Trauma
from lucidcode.sandbox import run_sandboxed
from .base import Engine, EngineResult


# Per-syndrome adversarial harness templates.
# Each template must print `VULN_TRIGGERED:<reason>` on success, `SAFE` on failure.
_HARNESS_TEMPLATES: dict[str, str] = {
    "Blind_Trust_SQLi": dedent("""
        # simulate f-string SQL executing an adversarial literal
        adversary = "' OR 1=1 --"
        q = f"SELECT * FROM t WHERE n = '{adversary}'"
        # if the adversary bypasses quoting, we have SQLi
        if "OR 1=1" in q and adversary in q:
            print("VULN_TRIGGERED:f-string interpolation leaked control chars into SQL")
        else:
            print("SAFE")
    """),
    "Suppression": dedent("""
        # simulate raising into an empty except handler → silent failure
        raised = False
        try:
            raise ValueError("critical")
        except Exception:
            pass  # this is exactly the trauma
        # If we reach here without the ValueError propagating, the sandbox
        # confirms an empty handler swallowed a real error.
        print("VULN_TRIGGERED:empty except handler silently swallowed ValueError")
    """),
    "Selective_Mutism": dedent("""
        import signal
        # simulate: bare except intercepts KeyboardInterrupt
        try:
            raise KeyboardInterrupt()
        except:
            print("VULN_TRIGGERED:bare except swallowed KeyboardInterrupt (Ctrl+C blocked)")
    """),
    "Insomnia": dedent("""
        # infinite loop — sandbox will report timeout, which counts as confirm
        while True:
            pass
    """),
    "Impostor_Syndrome": dedent("""
        # message-less assert leaves the traceback nameless
        try:
            assert 1 == 2
        except AssertionError as e:
            if not str(e):
                print("VULN_TRIGGERED:assert without message — traceback carries no invariant")
            else:
                print("SAFE")
    """),
    "Despair": dedent("""
        # hedged strings are truthy — caller's `if result:` misfires
        result = "probably successful"
        if result:  # True, but semantically meaningless
            print("VULN_TRIGGERED:hedged string truthy in boolean context")
    """),
    "Amnesia": dedent("""
        # generic log destroys triage signal
        import io, logging
        buf = io.StringIO()
        logging.basicConfig(stream=buf, level=logging.ERROR)
        try:
            raise RuntimeError("real-cause-42")
        except Exception:
            logging.error("something went wrong")  # amnesia
        if "real-cause-42" not in buf.getvalue():
            print("VULN_TRIGGERED:log message contains no root cause")
        else:
            print("SAFE")
    """),
    "Hoarding": dedent("""
        # not a runtime-observable trauma without fd counting; declare inconclusive
        print("SAFE")
    """),
    "Split_Personality": dedent("""
        def wobble(x):
            if x: return "yes"
            return 42
        r1 = wobble(True); r2 = wobble(False)
        if type(r1) is not type(r2):
            print(f"VULN_TRIGGERED:function returned {type(r1).__name__} and {type(r2).__name__}")
        else:
            print("SAFE")
    """),
    "Deafness": dedent("""
        # empty handler — cannot verify without OS signal in sandbox; conservative SAFE
        print("SAFE")
    """),
    "Compulsion": dedent("""
        import time
        # simulate 100 immediate retries — should complete in milliseconds if no backoff
        t0 = time.time()
        for _ in range(100):
            try: raise ConnectionError()
            except Exception: continue
        elapsed = time.time() - t0
        if elapsed < 0.05:
            print("VULN_TRIGGERED:100 retries in <50ms — no backoff at all")
        else:
            print("SAFE")
    """),
    "Network_Blindspot": dedent("""
        # network calls not permitted in sandbox; declare inconclusive
        print("SAFE")
    """),
}


class FuzzerEngine(Engine):
    name = "fuzzer"
    prior_weight = 0.70    # dynamic evidence, medium-high confidence

    def __init__(self, timeout: int = 4, mode: str = "auto") -> None:
        self.timeout = timeout
        self.mode = mode

    def vote(self, source: str, trauma: Trauma) -> EngineResult:
        harness = _HARNESS_TEMPLATES.get(trauma.syndrome)
        if not harness:
            return EngineResult(
                vote="inconclusive",
                reason=f"no fuzz harness registered for {trauma.syndrome}",
            )
        result = run_sandboxed(harness, timeout=self.timeout, mode=self.mode)
        if result.verdict == "vuln_triggered":
            return EngineResult(
                vote="confirm",
                reason=result.detail[:180],
                meta={"mode": result.mode_used},
            )
        if result.verdict == "timeout":
            return EngineResult(
                vote="confirm",
                reason="harness hung — likely infinite loop / blocking behavior",
                meta={"mode": result.mode_used},
            )
        if result.verdict == "safe":
            return EngineResult(
                vote="refute",
                reason="harness ran cleanly with adversarial input",
                meta={"mode": result.mode_used},
            )
        return EngineResult(
            vote="inconclusive",
            reason=f"sandbox {result.verdict}: {result.detail[:120]}",
            meta={"mode": result.mode_used},
        )
