"""End-to-end therapy session test — synthetic + real projects."""
from pathlib import Path
import tempfile
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from lucidcode.therapy import run_session, render


def test(label: str, source: str = None, path: Path = None):
    if source is not None:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
        tmp.write(source); tmp.close()
        path = Path(tmp.name)
    outcome = run_session(path)
    print(f"\n{'=' * 70}\n{label}\n{'=' * 70}")
    print(f"  probed:     {outcome.total_assumptions_probed}")
    print(f"  survived:   {outcome.gate_survivors}")
    print(f"  upheld:     {outcome.skeptic_upholds}")
    print(f"  final:      {len(outcome.final_confessions)}")
    print(f"  latency:    {outcome.total_latency_ms} ms")
    print(f"  outcome:    {outcome.outcome_label}")
    if outcome.final_confessions:
        print("  confessions:")
        for c in outcome.final_confessions[:5]:
            print(f"    - line {c.line}: {c.confession_text}")
    if outcome.dropped:
        print(f"  dropped ({len(outcome.dropped)}): first 3:")
        for d in outcome.dropped[:3]:
            print(f"    - line {d['line']}: {d['stage']}/{d['verdict']} — {d['reason'][:70]}")
    return outcome


# ═══════════════════════════════════════════════════════════
# CONTROL — hand-crafted, we know the ground truth
# ═══════════════════════════════════════════════════════════
CONTROL = """
def divide(a, b):
    return a / b

def divide_guarded(a, b):
    if b == 0:
        return 0
    return a / b

def first(items):
    return items[0]

def first_guarded(items):
    if not items:
        return None
    return items[0]

def read(path):
    return open(path).read()

def lookup(data):
    return data['id']
"""

test("SYNTHETIC control — 6 functions, 3 guarded, 3 vulnerable", source=CONTROL)

# ═══════════════════════════════════════════════════════════
# REAL PROJECT 1 — MobeFace backend/main.py (small, dense)
# ═══════════════════════════════════════════════════════════
real1 = Path("D:/project/mobeface/backend/main.py")
if real1.exists():
    test(f"REAL — {real1}", path=real1)
else:
    print(f"skip: {real1} not found")

# ═══════════════════════════════════════════════════════════
# REAL PROJECT 2 — NEXUS-AI core/runner.py
# ═══════════════════════════════════════════════════════════
real2 = Path("D:/project/suportagent/core/runner.py")
if real2.exists():
    test(f"REAL — {real2}", path=real2)
else:
    print(f"skip: {real2} not found")

# ═══════════════════════════════════════════════════════════
# REAL PROJECT 3 — gps backend/nexus_secops.py
# ═══════════════════════════════════════════════════════════
real3 = Path("D:/project/gps/backend/nexus_secops.py")
if real3.exists():
    test(f"REAL — {real3}", path=real3)
else:
    print(f"skip: {real3} not found")
