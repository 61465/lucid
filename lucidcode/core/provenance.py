"""
Provenance tagger for LLM confessions.

Every confession sentence is classified as one of:
    ast_evidence         — anchored to a specific line/AST fact
    osint_evidence       — anchored to a real threat-intel lookup
    hedged_speculation   — plausible narrative without hard anchor (LOW trust)

Rendering helpers turn spans into ANSI or HTML for terminal / web UI.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Literal

Kind = Literal["ast_evidence", "osint_evidence", "hedged_speculation"]


@dataclass
class ProvenanceSpan:
    text: str
    kind: Kind
    anchor: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


_HEDGE_WORDS = {
    "might", "could", "possibly", "maybe", "probably", "perhaps",
    "appears", "seems", "arguably", "presumably",
}
_OSINT_MARKERS = {
    "greynoise", "urlscan", "leakix", "publicwww",
    "mirai", "c2", "known scanner", "known-benign", "malicious",
    "threat intel", "iоc", "ioc", "botnet",
}
_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+")


def _split_sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENT_SPLIT.split(text.strip()) if s.strip()]


def tag_confession(
    confession_text: str,
    trauma: dict,
    osint_facts: list[dict] | None = None,
) -> list[ProvenanceSpan]:
    line_anchor = str(trauma.get("line", "") or "")
    facts = osint_facts or []
    fact_snippets: list[tuple[str, str]] = [
        ((f.get("summary") or "").lower(), (f.get("source") or "osint"))
        for f in facts
        if f.get("summary")
    ]

    spans: list[ProvenanceSpan] = []
    for sentence in _split_sentences(confession_text):
        low = sentence.lower()

        # Rule 3: hedges override every other tag (safe default)
        if any(re.search(rf"\b{re.escape(h)}\b", low) for h in _HEDGE_WORDS):
            spans.append(ProvenanceSpan(sentence, "hedged_speculation"))
            continue

        # Rule 2: OSINT markers OR fact-summary substring match
        matched_source = ""
        if any(m in low for m in _OSINT_MARKERS):
            matched_source = "osint"
        else:
            for snip, source in fact_snippets:
                if snip and (snip in low or _shared_tokens(snip, low) >= 3):
                    matched_source = source
                    break
        if matched_source:
            spans.append(ProvenanceSpan(sentence, "osint_evidence", matched_source))
            continue

        # Rule 1: AST anchor if line number appears verbatim
        if line_anchor and re.search(rf"\bline\s+{re.escape(line_anchor)}\b", low):
            spans.append(ProvenanceSpan(sentence, "ast_evidence", f"line {line_anchor}"))
            continue

        # Rule 4: safe default
        spans.append(ProvenanceSpan(sentence, "hedged_speculation"))

    return spans


def _shared_tokens(a: str, b: str) -> int:
    ta = set(re.findall(r"\w{4,}", a))
    tb = set(re.findall(r"\w{4,}", b))
    return len(ta & tb)


# ─── renderers ─────────────────────────────────────────────
_ANSI = {
    "ast_evidence":       "\033[38;5;220m",   # gold
    "osint_evidence":     "\033[38;5;196m",   # red
    "hedged_speculation": "\033[38;5;244m",   # gray
}
_RESET = "\033[0m"


def render_ansi(spans: list[ProvenanceSpan]) -> str:
    return " ".join(f"{_ANSI[s.kind]}{s.text}{_RESET}" for s in spans)


_HTML_CLASS = {
    "ast_evidence":       "span-ast",
    "osint_evidence":     "span-osint",
    "hedged_speculation": "span-hedge",
}


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def render_html(spans: list[ProvenanceSpan]) -> str:
    out = []
    for s in spans:
        cls = _HTML_CLASS[s.kind]
        title = f' title="{_esc(s.anchor)}"' if s.anchor else ""
        out.append(f'<span class="{cls}"{title}>{_esc(s.text)}</span>')
    return " ".join(out)


if __name__ == "__main__":
    demo_conf = (
        "I confessed at line 6: I called out without a clock. "
        "GreyNoise reports 3 sightings of this host by Mirai variants. "
        "This code might be fine in production. "
        "I sleep well knowing nothing."
    )
    trauma = {"line": 6}
    spans = tag_confession(demo_conf, trauma)
    for sp in spans:
        print(f"[{sp.kind:20s}] anchor={sp.anchor or '-':10s} :: {sp.text}")
    print()
    print("--- ANSI ---")
    print(render_ansi(spans))
    print()
    print("--- HTML ---")
    print(render_html(spans))
