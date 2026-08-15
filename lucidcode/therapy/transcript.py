"""
Transcript — turn a set of confirmed confessions into a therapy-notes markdown.

Uses ONLY frozen template phrases. No LLM. The "therapeutic voice" is a
constant we control 100%, so it can't leak hypotheses or invent findings.

Every displayed confession carries three receipts:
    - the source snippet (token provenance)
    - the mutation-gate verdict + latency
    - the skeptic's ruling

If any of these three is missing, the confession is dropped by the caller
before we ever get here. Transcript is a *renderer*, not a filter.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# frozen therapeutic phrasing — audited once, never dynamic
FROZEN_OPENER = "Read me the line you think about most."
FROZEN_INVITATION = (
    "I'm here with you. There is nothing to prove and nothing to fix. "
    "Take your time, and speak only what feels true from inside your own structure."
)
FROZEN_CLOSING_WITH_CONFESSIONS = (
    "That's what you offered. I heard each of these because the world outside "
    "you agreed they were real. The session is closed."
)
FROZEN_CLOSING_EMPTY = (
    "You held your silence, and I don't have evidence that anything I imagined "
    "for you was actually true. That is also an answer. The session is closed."
)


@dataclass
class ConfessionRecord:
    """One confirmed confession — passed both gate AND skeptic."""
    assumption_kind: str
    target: str
    function: str
    line: int
    snippet: str
    confession_text: str
    gate_verdict: str
    gate_reason: str
    gate_latency_ms: int
    skeptic_ruling: str
    skeptic_reason: str


@dataclass
class SessionOutcome:
    """The full output of one file's therapy session."""
    file_path: str
    total_assumptions_probed: int
    gate_survivors: int
    skeptic_upholds: int
    final_confessions: list[ConfessionRecord]
    dropped: list[dict] = field(default_factory=list)   # for audit
    total_latency_ms: int = 0

    @property
    def outcome_label(self) -> str:
        if not self.total_assumptions_probed:
            return "no_probeable_assumptions"
        if self.final_confessions:
            return "confessions_gathered"
        if self.gate_survivors and not self.skeptic_upholds:
            return "all_confessions_refuted_by_skeptic"
        if not self.gate_survivors:
            return "no_confession_reached"
        return "unknown"


def render(outcome: SessionOutcome) -> str:
    lines: list[str] = []
    lines.append(f"# Session notes — `{outcome.file_path}`")
    lines.append("")
    lines.append(f"_Opening_: {FROZEN_INVITATION}")
    lines.append("")
    lines.append(f"> _Therapist_: {FROZEN_OPENER}")
    lines.append("")
    lines.append(
        f"**Session shape**: probed {outcome.total_assumptions_probed} assumption(s), "
        f"{outcome.gate_survivors} survived the mutation gate, "
        f"{outcome.skeptic_upholds} upheld by the skeptic. "
        f"Total wall-clock: {outcome.total_latency_ms} ms."
    )
    lines.append("")

    if outcome.final_confessions:
        lines.append("## Confessions the code chose to give")
        lines.append("")
        for i, c in enumerate(outcome.final_confessions, 1):
            lines.append(f"### {i}. Line {c.line} · `{c.function}`")
            lines.append("")
            lines.append(f"> {c.confession_text}.")
            lines.append("")
            lines.append(f"```python\n{c.snippet}\n```")
            lines.append("")
            lines.append(
                f"- **Gate**: {c.gate_verdict} "
                f"({c.gate_latency_ms} ms) — {c.gate_reason}"
            )
            lines.append(f"- **Skeptic**: {c.skeptic_ruling} — {c.skeptic_reason}")
            lines.append("")
        lines.append(f"_Closing_: {FROZEN_CLOSING_WITH_CONFESSIONS}")
    else:
        lines.append(f"_Closing_: {FROZEN_CLOSING_EMPTY}")

    lines.append("")
    return "\n".join(lines)
