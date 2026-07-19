r"""
Network-code enrichment via cyberlab.osint (GreyNoise / urlscan / Leakix).

When a Network_Blindspot trauma fires on `requests.get(URL)`, we:
    1. Re-parse the source, find the Call at trauma["line"], extract URL literal.
    2. Reduce URL to a hostname.
    3. Call cyberlab.osint.combined(host) — cached per host per process.
    4. If ANY source returned actionable signal, append a threat-intel sentence
       to the confession; otherwise return the original.

The cyberlab.osint module lives in a sibling project (D:\project\suportagent).
We import it with a guarded sys.path insert so LucidCode still runs if it's
missing (enrichment simply degrades to a no-op).
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# ─── guarded import of cyberlab.osint ─────────────────────────
_CYBERLAB_ROOT = Path(r"D:\project\suportagent")
_osint = None
try:
    if _CYBERLAB_ROOT.exists() and str(_CYBERLAB_ROOT) not in sys.path:
        sys.path.insert(0, str(_CYBERLAB_ROOT))
    from cyberlab import osint as _osint  # type: ignore
except Exception:
    _osint = None

_CACHE: dict[str, dict] = {}


def extract_host(source: str, line: int) -> Optional[str]:
    """Return the hostname from a network call at `line`, if any."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node, "lineno", -1) == line):
            continue
        if not node.args:
            continue
        first = node.args[0]
        url = None
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            url = first.value
        elif isinstance(first, ast.JoinedStr):
            # take the constant prefix; often the scheme+host live there
            parts = [v.value for v in first.values
                     if isinstance(v, ast.Constant) and isinstance(v.value, str)]
            url = "".join(parts) if parts else None
        if not url:
            continue
        return _url_to_host(url)
    return None


def _url_to_host(url: str) -> Optional[str]:
    if not url:
        return None
    if "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if host:
            return host.lower()
    except Exception:
        pass
    # fallback regex: grab the token between :// and the next : or /
    m = re.match(r"^\w+://([^:/?#]+)", url)
    return m.group(1).lower() if m else None


def _lookup(host: str) -> dict:
    if host in _CACHE:
        return _CACHE[host]
    if not _osint:
        _CACHE[host] = {}
        return _CACHE[host]
    try:
        result = _osint.combined(host)
        _CACHE[host] = result if isinstance(result, dict) else {}
    except Exception as e:
        _CACHE[host] = {"error": str(e)[:120]}
    return _CACHE[host]


def _summarize_intel(intel: dict) -> str:
    """Produce a one-line human-readable summary; empty if nothing interesting."""
    if not intel or "sources" not in intel:
        return ""

    parts: list[str] = []
    src = intel.get("sources", {})

    gn = src.get("greynoise", {})
    if gn.get("ok"):
        raw = gn.get("raw") or {}
        cls = raw.get("classification", "")
        name = raw.get("name", "")
        if cls and cls not in ("unknown", "benign"):
            parts.append(f"GreyNoise: classified {cls}" + (f" ({name})" if name else ""))

    us = src.get("urlscan", {})
    if us.get("ok"):
        raw = us.get("raw") or {}
        results = raw.get("results", []) if isinstance(raw, dict) else []
        if results:
            parts.append(f"urlscan: {len(results)} historical detonations")

    lx = src.get("leakix", {})
    if lx.get("ok"):
        raw = lx.get("raw") or {}
        leaks = 0
        for e in (raw.get("Events") or raw.get("events") or []):
            if (e.get("event_type") or "").lower() == "leak":
                leaks += 1
        if leaks:
            parts.append(f"Leakix: {leaks} leak event(s)")

    return " · ".join(parts)


def enrich_trauma(source: str, trauma: dict) -> str:
    """Return an enriched confession string (or the original if no signal)."""
    if trauma.get("syndrome") != "Network_Blindspot":
        return trauma.get("confession", "")

    host = extract_host(source, trauma.get("line", -1))
    if not host:
        return trauma.get("confession", "")

    intel = _lookup(host)
    summary = _summarize_intel(intel)
    if not summary:
        return trauma.get("confession", "")

    base = trauma.get("confession", "")
    return (
        f"{base} Worse — {summary}. "
        "My blind trust is not just fragile — it may already be compromised."
    )


if __name__ == "__main__":
    demo = 'import requests\ndef f():\n    return requests.get("http://1.1.1.1/x")\n'
    print("host =", extract_host(demo, 3))
    print("cyberlab.osint available:", _osint is not None)
    t = {"syndrome": "Network_Blindspot", "line": 3,
         "confession": "I confessed at line 3: I called out without a clock."}
    print("enriched:", enrich_trauma(demo, t))
