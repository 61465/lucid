"""
LucidCode v4 — Syndrome Registry (12 syndromes, Python-first)
=============================================================

Each syndrome is a psychiatric metaphor for a code trauma:
- name         : PascalCase psychiatric label
- severity     : CRITICAL / HIGH / MEDIUM / LOW
- description  : one-line, human-readable
- detect(tree) : yields Trauma dicts with {line, evidence, predicate, adversary}
- confession   : first-person template with {line} placeholder

The Fuzzer consumes `adversary` to construct malicious test inputs.
The AST Re-Verifier re-runs `detect()` deterministically as a sanity gate.

Registration is decorator-driven so community can add syndromes without
touching the engine. Example third-party syndrome:

    from lucidcode.syndromes.registry import register_syndrome

    @register_syndrome("HighAnxiety", severity="MEDIUM")
    def detect_high_anxiety(tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Try) and len(node.handlers) > 5:
                yield {
                    "line": node.lineno,
                    "evidence": "try block guards more than 5 exception types",
                    "predicate": {"kind": "over_guarded", "line": node.lineno},
                    "adversary": "raise a genuinely novel exception type",
                }
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Syndrome:
    name: str
    severity: Severity
    description: str
    confession: str
    detect: Callable[[ast.AST], Iterable[dict]]
    metadata: dict = field(default_factory=dict)


SYNDROMES: dict[str, Syndrome] = {}


def register_syndrome(name: str, severity: str, description: str, confession: str,
                      **metadata) -> Callable:
    """Decorator: attach an AST detector to the registry."""
    def _wrap(detect_fn: Callable[[ast.AST], Iterable[dict]]):
        SYNDROMES[name] = Syndrome(
            name=name,
            severity=Severity(severity),
            description=description,
            confession=confession,
            detect=detect_fn,
            metadata=metadata,
        )
        return detect_fn
    return _wrap


# ══════════════════════════════════════════════════════════════════
# Helper utilities
# ══════════════════════════════════════════════════════════════════
_SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|REPLACE)\b.*\b(FROM|INTO|SET|WHERE|VALUES|TABLE)\b",
    re.IGNORECASE | re.DOTALL,
)


def _attr_dotted(node: ast.AST) -> str:
    """Resolve x.y.z Attribute chain to a dotted string; empty on failure."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.insert(0, node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.insert(0, node.id)
        return ".".join(parts)
    return ""


def _has_break_or_return(body) -> bool:
    for n in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(n, (ast.Break, ast.Return)):
            return True
    return False


# ══════════════════════════════════════════════════════════════════
# ORIGINAL FOUR (v3)
# ══════════════════════════════════════════════════════════════════

@register_syndrome(
    "Suppression",
    severity="HIGH",
    description="Empty exception handler — errors born and buried in the same breath.",
    confession="I confessed at line {line}: I caught an exception and then said nothing. "
               "Every scream is muffled the moment it starts. What am I hiding?",
)
def _suppression(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.ExceptHandler):
            body = n.body
            empty = (not body) or (len(body) == 1 and isinstance(body[0], ast.Pass))
            if empty:
                yield {
                    "line": n.lineno,
                    "evidence": "except handler is empty or only `pass`",
                    "predicate": {"kind": "empty_handler", "line": n.lineno},
                    "adversary": "raise inside the try block and observe the silence",
                }


@register_syndrome(
    "Blind_Trust_SQLi",
    severity="CRITICAL",
    description="SQL statement built by f-string — user data becomes control-flow.",
    confession="I confessed at line {line}: I built SQL by string concatenation, "
               "believing every input is kind. One quote will end me.",
)
def _blind_trust_sqli(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.JoinedStr):
            literal = "".join(
                v.value for v in n.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
            if _SQL_KEYWORDS.search(literal):
                yield {
                    "line": n.lineno,
                    "evidence": f"f-string SQL: {literal.strip()[:100]}",
                    "predicate": {"kind": "fstring_sql", "line": n.lineno, "literal": literal},
                    "adversary": "' OR 1=1 --",
                }


@register_syndrome(
    "Amnesia",
    severity="MEDIUM",
    description="Generic error log — the trauma is remembered but never identified.",
    confession="I confessed at line {line}: something went wrong — I don't remember what. "
               "My memory is the word 'error' and nothing more.",
)
def _amnesia(tree):
    for handler in ast.walk(tree):
        if not isinstance(handler, ast.ExceptHandler):
            continue
        for stmt in handler.body[:2]:
            if not (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)):
                continue
            fn = stmt.value.func
            name = getattr(fn, "attr", None) or getattr(fn, "id", None) or ""
            if name in ("log_error", "print", "logging", "log", "error") and stmt.value.args:
                arg = stmt.value.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    msg = arg.value.lower()
                    if len(arg.value) < 60 and any(w in msg for w in ("wrong", "error", "oops", "failed")):
                        yield {
                            "line": handler.lineno,
                            "evidence": f"generic log message: {arg.value!r}",
                            "predicate": {"kind": "generic_log", "line": handler.lineno,
                                          "msg": arg.value},
                            "adversary": "inspect logs after a real failure — signal is absent",
                        }


@register_syndrome(
    "Despair",
    severity="LOW",
    description="Return value hedges — uncertainty leaks to every caller.",
    confession="I confessed at line {line}: I return 'probably successful'. "
               "I do not know. Every caller now inherits my doubt.",
)
def _despair(tree):
    hedges = ("probably", "maybe", "might", "unsure", "unknown", "possibly")
    for n in ast.walk(tree):
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant) \
                and isinstance(n.value.value, str):
            text = n.value.value.lower()
            hits = [w for w in hedges if w in text]
            if hits:
                yield {
                    "line": n.lineno,
                    "evidence": f"hedged return: {n.value.value!r}",
                    "predicate": {"kind": "hedge_return", "line": n.lineno,
                                  "hedges": hits, "value": n.value.value},
                    "adversary": "caller cannot branch on truthiness — force a real boolean",
                }


# ══════════════════════════════════════════════════════════════════
# EIGHT NEW SYNDROMES (v4)
# ══════════════════════════════════════════════════════════════════

_HTTP_SYNC = {"requests.get", "requests.post", "requests.put", "requests.delete",
              "requests.patch", "requests.head", "requests.request",
              "httpx.get", "httpx.post", "httpx.request",
              "urllib.request.urlopen"}


@register_syndrome(
    "Network_Blindspot",
    severity="HIGH",
    description="HTTP call without timeout — one slow server freezes the whole app.",
    confession="I confessed at line {line}: I call {target} without a timeout. "
               "If the server hangs, I wait forever. My blind trust has no clock.",
)
def _network_blindspot(tree):
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        target = _attr_dotted(n.func)
        if not target or target not in _HTTP_SYNC:
            continue
        has_timeout = any(kw.arg == "timeout" for kw in n.keywords)
        if not has_timeout:
            yield {
                "line": n.lineno,
                "evidence": f"{target}() without timeout",
                "predicate": {"kind": "no_timeout", "line": n.lineno, "call": target},
                "adversary": "point the URL at a server that accepts the TCP connection then never replies",
                "target": target,
            }


@register_syndrome(
    "Insomnia",
    severity="MEDIUM",
    description="Infinite loop with no exit condition — the code cannot rest.",
    confession="I confessed at line {line}: I loop forever, and I do not know how to stop. "
               "No break, no return, no interrupt — I will consume every cycle you give me.",
)
def _insomnia(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.While) and isinstance(n.test, ast.Constant) and n.test.value is True:
            # while True with no break/return anywhere inside
            if not _has_break_or_return(n.body):
                yield {
                    "line": n.lineno,
                    "evidence": "while True without break/return",
                    "predicate": {"kind": "unbounded_loop", "line": n.lineno},
                    "adversary": "run the function; measure CPU forever",
                }


@register_syndrome(
    "Hoarding",
    severity="HIGH",
    description="Resource opened outside `with` and never closed — file descriptors leak.",
    confession="I confessed at line {line}: I opened a resource and forgot to release it. "
               "I keep every handle, every socket, every file — until nothing else can breathe.",
)
def _hoarding(tree):
    resource_ctors = {"open", "socket.socket"}
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        # collect all `open`/`socket.socket` calls not inside `with`
        with_calls: set[int] = set()
        for wnode in ast.walk(fn):
            if isinstance(wnode, ast.With):
                for item in wnode.items:
                    if isinstance(item.context_expr, ast.Call):
                        with_calls.add(id(item.context_expr))
        # look at bare Call/Assign whose rhs is a resource ctor and not tracked
        close_names: set[str] = set()
        for c in ast.walk(fn):
            if isinstance(c, ast.Call):
                target = _attr_dotted(c.func) or (c.func.id if isinstance(c.func, ast.Name) else "")
                if target.endswith(".close"):
                    if isinstance(c.func, ast.Attribute) and isinstance(c.func.value, ast.Name):
                        close_names.add(c.func.value.id)

        for asn in ast.walk(fn):
            if not isinstance(asn, ast.Assign):
                continue
            if not (isinstance(asn.value, ast.Call) and id(asn.value) not in with_calls):
                continue
            target = _attr_dotted(asn.value.func) or (
                asn.value.func.id if isinstance(asn.value.func, ast.Name) else ""
            )
            if target not in resource_ctors:
                continue
            # is there a close() on the same name in scope?
            names = [t.id for t in asn.targets if isinstance(t, ast.Name)]
            if any(n in close_names for n in names):
                continue
            yield {
                "line": asn.lineno,
                "evidence": f"{target}() outside `with` and no matching .close() in function",
                "predicate": {"kind": "unclosed_resource", "line": asn.lineno, "call": target},
                "adversary": "call the function in a loop and watch fd count climb",
            }


@register_syndrome(
    "Split_Personality",
    severity="MEDIUM",
    description="Function returns literals of >1 distinct primitive type — callers cannot branch safely.",
    confession="I confessed at line {line}: I return a string one day, None the next, "
               "and an integer when the mood strikes. No caller can trust what I hand back.",
)
def _split_personality(tree):
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        seen_types: set[str] = set()
        for r in ast.walk(fn):
            if not (isinstance(r, ast.Return) and r.value is not None):
                continue
            v = r.value
            if isinstance(v, ast.Constant):
                seen_types.add(type(v.value).__name__)
            elif isinstance(v, (ast.Dict, ast.DictComp)):
                seen_types.add("dict")
            elif isinstance(v, (ast.List, ast.ListComp)):
                seen_types.add("list")
            elif isinstance(v, (ast.Set, ast.SetComp)):
                seen_types.add("set")
            elif isinstance(v, ast.Tuple):
                seen_types.add("tuple")
        if len(seen_types) >= 2:
            yield {
                "line": fn.lineno,
                "evidence": f"{fn.name}() returns literals of types: {sorted(seen_types)}",
                "predicate": {"kind": "mixed_return_types", "line": fn.lineno,
                              "fn": fn.name, "types": sorted(seen_types)},
                "adversary": "call the function repeatedly and assert isinstance() — will fail",
            }


@register_syndrome(
    "Deafness",
    severity="HIGH",
    description="Signal handler is empty — the process cannot hear the OS.",
    confession="I confessed at line {line}: I registered a signal handler and gave it nothing to do. "
               "The kernel knocks and I do not answer.",
)
def _deafness(tree):
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and _attr_dotted(n.func) == "signal.signal"):
            continue
        if len(n.args) < 2:
            continue
        handler = n.args[1]
        # inline lambda: signal.signal(SIGINT, lambda *a: None)
        if isinstance(handler, ast.Lambda):
            body = handler.body
            if isinstance(body, ast.Constant) and body.value is None:
                yield {
                    "line": n.lineno,
                    "evidence": "signal.signal(..., lambda: None)",
                    "predicate": {"kind": "empty_signal_handler", "line": n.lineno},
                    "adversary": "send SIGINT — the process cannot shut down cleanly",
                }
        # named handler defined nearby
        elif isinstance(handler, ast.Name):
            for fn in ast.walk(tree):
                if isinstance(fn, ast.FunctionDef) and fn.name == handler.id:
                    body = fn.body
                    if not body or (len(body) == 1 and isinstance(body[0], ast.Pass)):
                        yield {
                            "line": n.lineno,
                            "evidence": f"signal handler `{fn.name}` has empty body",
                            "predicate": {"kind": "empty_signal_handler", "line": n.lineno,
                                          "handler": fn.name},
                            "adversary": "send SIGTERM — the process ignores it",
                        }


@register_syndrome(
    "Compulsion",
    severity="MEDIUM",
    description="Retry loop with no backoff — bombards a fragile downstream.",
    confession="I confessed at line {line}: I retry immediately, again and again. "
               "I do not pause, I do not learn. I turn one failure into a stampede.",
)
def _compulsion(tree):
    for loop in ast.walk(tree):
        if not isinstance(loop, (ast.For, ast.While)):
            continue
        has_retry_shape = False
        has_sleep = False
        for inner in ast.walk(loop):
            if isinstance(inner, ast.Try):
                has_retry_shape = True
            if isinstance(inner, ast.Call):
                target = _attr_dotted(inner.func)
                if target in ("time.sleep", "asyncio.sleep", "trio.sleep"):
                    has_sleep = True
        if has_retry_shape and not has_sleep:
            yield {
                "line": loop.lineno,
                "evidence": "retry-shaped loop (try/except inside) with no sleep between iterations",
                "predicate": {"kind": "retry_no_backoff", "line": loop.lineno},
                "adversary": "make the wrapped call always fail — watch the downstream get hammered",
            }


@register_syndrome(
    "Impostor_Syndrome",
    severity="LOW",
    description="Assert without message — invariant fails, no one knows which.",
    confession="I confessed at line {line}: I asserted, but I did not explain. "
               "When I fail, all you will see is `AssertionError`. I did not say what I meant.",
)
def _impostor_syndrome(tree):
    for n in ast.walk(tree):
        if isinstance(n, ast.Assert) and n.msg is None:
            yield {
                "line": n.lineno,
                "evidence": "assert without message",
                "predicate": {"kind": "assert_no_msg", "line": n.lineno},
                "adversary": "trigger the failing assertion — the traceback names no invariant",
            }


@register_syndrome(
    "Selective_Mutism",
    severity="CRITICAL",
    description="Bare except or `except BaseException` — swallows SystemExit and KeyboardInterrupt.",
    confession="I confessed at line {line}: I catch every exception, even the ones meant to stop me. "
               "You cannot Ctrl+C me. You cannot sys.exit me. I refuse to die.",
)
def _selective_mutism(tree):
    for n in ast.walk(tree):
        if not isinstance(n, ast.ExceptHandler):
            continue
        # bare except (n.type is None) OR except BaseException / SystemExit / KeyboardInterrupt
        target = None
        if n.type is None:
            target = "bare"
        elif isinstance(n.type, ast.Name):
            if n.type.id in ("BaseException", "SystemExit", "KeyboardInterrupt"):
                target = n.type.id
        if target:
            yield {
                "line": n.lineno,
                "evidence": f"except handler catches {target}",
                "predicate": {"kind": "swallow_baseexception", "line": n.lineno, "kind_type": target},
                "adversary": "send KeyboardInterrupt to a long-running loop wrapped by this except",
            }


# ══════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════

def detect_all(source: str) -> list[dict]:
    """Run every registered syndrome against `source` and return trauma dicts."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [{
            "syndrome": "Syntax_Error",
            "line": e.lineno or 0,
            "evidence": f"{e.msg}",
            "predicate": {"kind": "syntax_error"},
            "severity": "CRITICAL",
            "confession": "I confessed: I do not parse. My grammar is broken. "
                          "I cannot even begin to know myself.",
        }]

    out: list[dict] = []
    _tid = 0
    for syndrome in SYNDROMES.values():
        for hit in syndrome.detect(tree):
            _tid += 1
            hit_out = {
                "id": f"T{_tid}",
                "syndrome": syndrome.name,
                "severity": syndrome.severity.value,
                "confession": syndrome.confession.format(
                    line=hit.get("line", 0),
                    target=hit.get("target", "the network"),
                ),
                **hit,
            }
            out.append(hit_out)
    return out


if __name__ == "__main__":
    import json, sys
    src = sys.stdin.read() if not sys.stdin.isatty() else sys.argv[1] if len(sys.argv) > 1 else ""
    if not src:
        print("Usage: echo <code> | python -m lucidcode.syndromes.registry")
        sys.exit(1)
    hits = detect_all(src)
    print(f"# {len(hits)} trauma(s) detected across {len(SYNDROMES)} syndromes:")
    print(json.dumps(hits, indent=2, default=str))
