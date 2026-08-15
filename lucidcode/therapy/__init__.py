"""
LucidCode therapy layer.

The world's first evidence-gated code confession engine.
Every confession we display has:
    1. Survived a mutation gate (adversarial execution)
    2. Been upheld by a deterministic skeptic
The "therapist voice" is frozen text; the truth is machine-verified.
"""
from .assumptions import Assumption, extract_assumptions  # noqa: F401
from .mutation_gate import test_assumption, GateResult  # noqa: F401
from .skeptic import judge, SkepticVerdict  # noqa: F401
from .session import run_session  # noqa: F401
from .transcript import (  # noqa: F401
    ConfessionRecord, SessionOutcome, render,
    FROZEN_OPENER, FROZEN_INVITATION,
)
