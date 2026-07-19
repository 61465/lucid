"""
Devil's Advocate Engine — LLM cross-check with mandatory provider diversity.

The devil MUST run on a different provider family than the LLM that
produced the confession. This defeats within-family agreement bias:
Mistral confessing to Mistral almost always agrees.

Providers are grouped into "families":
    - mistral: naraya mistral-* + mimo-*
    - openai:  gpt-* + o1-* + openai/gpt-oss-*
    - anthropic: claude-*
    - meta:    llama-*
    - moonshot: kimi-*
    - deepseek: deepseek-*

If a preferred family is unavailable (no key / all fallbacks fail), the devil
returns `inconclusive` rather than falling back to the same family.

To keep this file lightweight and testable, the actual HTTP call is
delegated to a `caller` callable — you inject one of:
    - a real client (naraya router / groq / openai)
    - a stub for tests

The Constitution (12 rules) is embedded here so the prompt is deterministic.
"""
from __future__ import annotations

import os
import re
from enum import Enum
from typing import Callable

from lucidcode.core.trauma import Trauma
from .base import Engine, EngineResult


class ProviderFamily(str, Enum):
    MISTRAL = "mistral"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    META = "meta"
    MOONSHOT = "moonshot"
    DEEPSEEK = "deepseek"
    UNKNOWN = "unknown"


def family_of_model(model: str) -> ProviderFamily:
    """Coarse mapping of model name → provider family."""
    m = (model or "").lower()
    if "mistral" in m or "mimo" in m:
        return ProviderFamily.MISTRAL
    if m.startswith("gpt-") or m.startswith("openai/") or "o1-" in m:
        return ProviderFamily.OPENAI
    if m.startswith("claude-"):
        return ProviderFamily.ANTHROPIC
    if "llama" in m:
        return ProviderFamily.META
    if "kimi" in m or "moonshot" in m:
        return ProviderFamily.MOONSHOT
    if "deepseek" in m:
        return ProviderFamily.DEEPSEEK
    return ProviderFamily.UNKNOWN


def pick_devil_family(confession_family: ProviderFamily,
                      available: list[ProviderFamily]) -> ProviderFamily | None:
    """Choose a Devil family strictly different from the confession family."""
    for fam in available:
        if fam != confession_family and fam != ProviderFamily.UNKNOWN:
            return fam
    return None


# ─────────────────────────────────────────────────────────────
# The Constitution — 12 rules the Devil MUST cite by number.
# ─────────────────────────────────────────────────────────────
DEVIL_CONSTITUTION = [
    "1. A confession without a specific line number is REFUTED.",
    "2. A confession that hedges ('might', 'could', 'may') is REFUTED.",
    "3. A confession must quote actual code text; imagined quotes are REFUTED.",
    "4. A confession citing a non-existent line is REFUTED.",
    "5. A confession contradicting the surrounding control-flow is REFUTED.",
    "6. A confession without a concrete adversarial input is REFUTED.",
    "7. A confession about behavior guarded elsewhere in the same function is REFUTED.",
    "8. A plausible-but-unproven confession is UNCERTAIN, never UPHELD.",
    "9. You may not invent behaviors, symbols, or facts not in the source.",
    "10. Common-sense arguments alone never justify UPHELD.",
    "11. Every REASON must cite at least one rule number from this constitution.",
    "12. Output format is sacred: single line, exact template.",
]


DEVIL_SYSTEM_PROMPT = """You are this code's DEFENSE ATTORNEY. Refute the confession
unless the code provides ironclad evidence. You operate under a 12-RULE
CONSTITUTION — every reply MUST cite at least one rule number.

CONSTITUTION:
{constitution}

Reply on ONE LINE using this exact template (no other text):
VERDICT:<UPHELD|REFUTED|UNCERTAIN>|REASON:<one short sentence citing at least one rule number>|GROUND:<line number or specific AST fact>|CODE:"<exact quoted code snippet ≤ 60 chars>"
"""


_VERDICT_RE = re.compile(
    r"VERDICT:\s*(UPHELD|REFUTED|UNCERTAIN)\s*\|\s*REASON:(.+?)\|\s*GROUND:(.+?)\|\s*CODE:(.+)",
    re.IGNORECASE | re.DOTALL,
)


class DevilEngine(Engine):
    name = "devil"
    prior_weight = 0.40   # LLM → lowest weight in Bayesian aggregation

    def __init__(
        self,
        caller: Callable[[str, str, str], str] | None = None,
        preferred_families: list[ProviderFamily] | None = None,
    ) -> None:
        """
        `caller(system_prompt, user_prompt, model) -> raw_text`
        `preferred_families` = ordered list of families to try; MUST differ from confession family.
        """
        self.caller = caller
        self.preferred_families = preferred_families or [
            ProviderFamily.MOONSHOT,
            ProviderFamily.OPENAI,
            ProviderFamily.META,
            ProviderFamily.DEEPSEEK,
            ProviderFamily.MISTRAL,
        ]

    def vote(self, source: str, trauma: Trauma) -> EngineResult:
        if not self.caller:
            return EngineResult(
                vote="inconclusive",
                reason="no LLM caller injected — devil offline",
            )

        confession_family = family_of_model(
            getattr(trauma, "confession_model", "") or os.environ.get("LUCID_CONFESSION_MODEL", "")
        )
        devil_family = pick_devil_family(confession_family, self.preferred_families)
        if not devil_family:
            return EngineResult(
                vote="inconclusive",
                reason="no cross-family devil available — provider diversity violated",
            )

        # Resolve a specific model within the chosen family (env-configurable).
        model = _resolve_model_for_family(devil_family)
        if not model:
            return EngineResult(
                vote="inconclusive",
                reason=f"no model resolved for family {devil_family.value}",
            )

        system_prompt = DEVIL_SYSTEM_PROMPT.format(
            constitution="\n".join(DEVIL_CONSTITUTION),
        )
        user_prompt = (
            f"CODE (verbatim):\n```python\n{source[:4000]}\n```\n\n"
            f"CONFESSION (line {trauma.line}, {trauma.syndrome}):\n"
            f"{trauma.confession or trauma.evidence}\n"
        )

        try:
            raw = self.caller(system_prompt, user_prompt, model) or ""
        except Exception as e:
            return EngineResult(
                vote="inconclusive",
                reason=f"devil call failed: {e}"[:180],
                provider=devil_family.value,
            )

        m = _VERDICT_RE.search(raw)
        if not m:
            return EngineResult(
                vote="inconclusive",
                reason=f"devil returned malformed verdict: {raw.strip()[:120]}",
                provider=devil_family.value,
            )

        verdict, reason, ground, quoted = m.groups()
        verdict = verdict.upper()
        pretty = f"{reason.strip()} · ground: {ground.strip()[:60]}"[:180]
        mapping = {"UPHELD": "confirm", "REFUTED": "refute", "UNCERTAIN": "inconclusive"}
        return EngineResult(
            vote=mapping.get(verdict, "inconclusive"),
            reason=pretty,
            provider=devil_family.value,
            meta={"model": model, "raw": raw.strip()[:400]},
        )


def _resolve_model_for_family(fam: ProviderFamily) -> str | None:
    """Env-driven model resolution — allows re-targeting without code change."""
    env_key = f"LUCID_DEVIL_MODEL_{fam.value.upper()}"
    if env_key in os.environ:
        return os.environ[env_key]
    defaults = {
        ProviderFamily.MISTRAL: "mistral-medium-3-5",
        ProviderFamily.OPENAI: "openai/gpt-oss-120b",
        ProviderFamily.META: "meta-llama/llama-4-maverick-17b-128e-instruct",
        ProviderFamily.MOONSHOT: "moonshotai/kimi-k2-instruct-0905",
        ProviderFamily.DEEPSEEK: "deepseek-r1-distill-llama-70b",
        ProviderFamily.ANTHROPIC: "claude-haiku-4-5",
    }
    return defaults.get(fam)
