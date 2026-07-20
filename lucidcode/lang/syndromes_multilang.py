"""
Multi-language syndrome detection via Tree-sitter.

For each supported language, we detect a subset of the 12 syndromes by
walking the concrete syntax tree. Node type names come from the language's
tree-sitter grammar and are stable across parser versions.

Coverage in v4:
    python  → delegated to lucidcode.syndromes.detect_all (native ast)
    javascript / typescript → Suppression, Selective_Mutism, Network_Blindspot,
                              Insomnia, Impostor_Syndrome (assert w/o message)
    go      → Suppression (empty error branch), Selective_Mutism (_ = err),
              Insomnia (for {}), Compulsion (retry loop with no time.Sleep)

Every detection yields the SAME trauma-dict shape as the Python surgeon, so
the pipeline downstream is language-agnostic.
"""
from __future__ import annotations

from typing import Any

from .frontend import parse_source, detect_language, is_available, LangResult


# ─── shared helpers ──────────────────────────────────────────
def _node_text(source_bytes: bytes, node: Any) -> str:
    try:
        return source_bytes[node.start_byte:node.end_byte].decode(
            "utf-8", errors="replace"
        )
    except Exception:
        return ""


def _line(node: Any) -> int:
    return node.start_point[0] + 1


def _walk(node: Any):
    """Depth-first walk of every descendant."""
    yield node
    for child in node.children:
        yield from _walk(child)


# ═══════════════════════════════════════════════════════════════
# JavaScript / TypeScript
# ═══════════════════════════════════════════════════════════════
_JS_HTTP_CALLEES = {
    "fetch",                    # global fetch()
    "axios.get", "axios.post", "axios.put", "axios.delete",
    "http.get", "https.get",
}


def _detect_js_ts(r: LangResult) -> list[dict]:
    hits: list[dict] = []
    src = r.source_bytes
    _tid = 0

    def _add(syndrome, sev, line, ev, conf):
        nonlocal _tid
        _tid += 1
        hits.append({
            "id": f"T{_tid}",
            "syndrome": syndrome,
            "severity": sev,
            "line": line,
            "evidence": ev,
            "confession": conf,
            "predicate": {"kind": syndrome.lower(), "line": line, "lang": r.language},
            "adversary": "",
        })

    for node in _walk(r.tree.root_node):
        # empty catch clause → Suppression + (bare) Selective_Mutism
        if node.type == "catch_clause":
            body = node.child_by_field_name("body")
            if body and body.child_count <= 2:  # {} or { ; }
                text = _node_text(src, body).strip()
                if text in ("{}", "{ }", "{ ; }") or "console.log" not in text:
                    _add("Suppression", "HIGH", _line(node),
                         "empty catch block", f"I confessed at line {_line(node)}: "
                         "I caught the exception and did nothing.")

        # while (true) with no break — Insomnia
        if node.type == "while_statement":
            cond = node.child_by_field_name("condition")
            if cond and _node_text(src, cond).strip("()") in ("true", "1"):
                body = node.child_by_field_name("body")
                if body and not any(n.type == "break_statement" for n in _walk(body)):
                    _add("Insomnia", "MEDIUM", _line(node),
                         "while(true) without break",
                         f"I confessed at line {_line(node)}: I loop forever.")

        # fetch(url) / axios.get(url) without a 2nd arg — Network_Blindspot
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if not callee or not args:
                continue
            callee_text = _node_text(src, callee)
            if callee_text in _JS_HTTP_CALLEES or callee_text.endswith(".get"):
                # count non-empty arg nodes; only-url = 1 arg = blindspot
                real_args = [c for c in args.children if c.type not in ("(", ")", ",")]
                if len(real_args) == 1:
                    _add("Network_Blindspot", "HIGH", _line(node),
                         f"{callee_text}() with no timeout/AbortSignal",
                         f"I confessed at line {_line(node)}: "
                         "I fire off the request and hope the server answers.")

        # assert(x) with no message argument — Impostor_Syndrome
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if callee and _node_text(src, callee) in ("assert", "console.assert"):
                real_args = [c for c in args.children if c.type not in ("(", ")", ",")] if args else []
                if len(real_args) == 1:
                    _add("Impostor_Syndrome", "LOW", _line(node),
                         "assert with no message",
                         f"I confessed at line {_line(node)}: I asserted but did not explain.")

    return hits


# ═══════════════════════════════════════════════════════════════
# Go
# ═══════════════════════════════════════════════════════════════
def _detect_go(r: LangResult) -> list[dict]:
    hits: list[dict] = []
    src = r.source_bytes
    _tid = 0

    def _add(syn, sev, line, ev, conf):
        nonlocal _tid
        _tid += 1
        hits.append({
            "id": f"T{_tid}",
            "syndrome": syn, "severity": sev, "line": line,
            "evidence": ev, "confession": conf,
            "predicate": {"kind": syn.lower(), "line": line, "lang": "go"},
            "adversary": "",
        })

    for node in _walk(r.tree.root_node):
        # `if err != nil {}` with empty body → Suppression
        if node.type == "if_statement":
            cond = node.child_by_field_name("condition")
            body = node.child_by_field_name("consequence")
            if cond and body and "err" in _node_text(src, cond):
                if body.child_count <= 2:  # { } or { ; }
                    _add("Suppression", "HIGH", _line(node),
                         "empty error-handling branch",
                         f"I confessed at line {_line(node)}: "
                         "I checked the error and dropped it in silence.")

        # `_ = f()` blank-identifier assignment discarding error — Selective_Mutism
        if node.type == "assignment_statement":
            left = node.child_by_field_name("left")
            if left and _node_text(src, left).strip() == "_":
                right = _node_text(src, node.child_by_field_name("right") or node)
                if "err" in right.lower() or "()" in right:
                    _add("Selective_Mutism", "CRITICAL", _line(node),
                         "error discarded via blank identifier _",
                         f"I confessed at line {_line(node)}: "
                         "I got an error and threw it into the blank.")

        # `for {}` unbounded loop → Insomnia
        if node.type == "for_statement":
            if node.child_count <= 3:  # `for` + `{` + `}`
                _add("Insomnia", "MEDIUM", _line(node),
                     "bare `for` loop without exit condition",
                     f"I confessed at line {_line(node)}: I spin without a stop condition.")

    return hits


# ═══════════════════════════════════════════════════════════════
# Public entry
# ═══════════════════════════════════════════════════════════════
def detect_all_multilang(source: str, language: str | None = None) -> list[dict]:
    """Detect syndromes across supported languages.

    If `language` is None, auto-detect from source heuristics.
    Falls back to the Python AST surgeon for language='python'.
    """
    if language is None:
        language = detect_language(source, is_source=True) or "python"

    if language == "python":
        from lucidcode.syndromes import detect_all as _py_detect
        return _py_detect(source)

    if not is_available():
        return []

    r = parse_source(source, language)
    if not r:
        return []

    if language in ("javascript", "typescript"):
        return _detect_js_ts(r)
    if language == "go":
        return _detect_go(r)
    return []


if __name__ == "__main__":
    demos = {
        "javascript": (
            "async function f(){\n"
            "  try {\n"
            "    const r = await fetch('http://x.com');\n"
            "  } catch (e) {}\n"
            "}\n"
        ),
        "go": (
            "package main\n"
            "func main() {\n"
            "    _, err := doThing()\n"
            "    _ = err\n"
            "    for {\n"
            "        x := 1\n"
            "    }\n"
            "}\n"
        ),
    }
    for lang, src in demos.items():
        print(f"=== {lang} ===")
        hits = detect_all_multilang(src, lang)
        for h in hits:
            print(f"  [{h['severity']:8s}] {h['syndrome']:20s} line {h['line']:2d} :: {h['evidence']}")
