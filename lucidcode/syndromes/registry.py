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


_SQL_SAFE_INTERPOLATION_NAMES = {
    "table", "table_name", "tbl", "col", "column", "field", "fields",
    "where_sql", "where_clause", "order_by", "limit_clause", "select_sql",
    "columns", "sort_by", "group_by",
}


def _sql_slot_name(node):
    """Resolve an f-string/BinOp interpolation slot to its identifier name."""
    v = node.value if isinstance(node, ast.FormattedValue) else node
    if isinstance(v, ast.Name):
        return v.id
    if isinstance(v, ast.Attribute):
        return v.attr
    if isinstance(v, ast.Call):
        return None
    return None


def _is_safe_slot(slot):
    n = _sql_slot_name(slot)
    return bool(n and n.lower() in _SQL_SAFE_INTERPOLATION_NAMES)


def _fstring_sql_literal(node):
    if not isinstance(node, ast.JoinedStr):
        return ""
    return "".join(
        v.value for v in node.values
        if isinstance(v, ast.Constant) and isinstance(v.value, str)
    )


@register_syndrome(
    "Blind_Trust_SQLi",
    severity="CRITICAL",
    description="SQL statement built by string interpolation — user data becomes control-flow.",
    confession="I confessed at line {line}: I built SQL by string concatenation, "
               "believing every input is kind. One quote will end me.",
)
def _blind_trust_sqli(tree):
    """Detect SQL injection across four Python interpolation vectors:
      (V1) f-string:    f"SELECT ... {uid}"
      (V2) % operator:  "SELECT ... %s" % uid
      (V3) .format():   "SELECT ... {}".format(uid)
      (V4) + concat:    "SELECT ... " + uid

    Skip when any of these safe conditions hold:
      (S1) literal contains ? / %s / %( placeholders — real params in use
      (S2) every interpolated slot resolves to a safe metavariable identifier
      (S3) all slots are Constants (pure formatting)
    """

    def _skip_placeholder(literal):
        return "?" in literal or "%s" in literal or "%(" in literal

    def _emit(kind, node, literal, slot_names):
        return {
            "line": node.lineno,
            "evidence": f"{kind} SQL with user-controlled interpolation: {literal.strip()[:100]}",
            "predicate": {"kind": kind, "line": node.lineno,
                          "literal": literal, "slot_names": slot_names},
            "adversary": "' OR 1=1 --",
        }

    for n in ast.walk(tree):
        # ─── V1: f-string ──────────────────────────────────
        if isinstance(n, ast.JoinedStr):
            literal = _fstring_sql_literal(n)
            if not _SQL_KEYWORDS.search(literal):
                continue
            if _skip_placeholder(literal):
                continue
            slots = [v for v in n.values if isinstance(v, ast.FormattedValue)]
            if not slots:
                continue
            slot_names = [_sql_slot_name(s) for s in slots]
            if all(name and name.lower() in _SQL_SAFE_INTERPOLATION_NAMES
                   for name in slot_names):
                continue
            yield _emit("fstring_sql", n, literal, slot_names)
            continue

        # ─── V2: "..." % var  or  "..." % (var, ...) ────────
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod):
            left = n.left
            if isinstance(left, ast.Constant) and isinstance(left.value, str):
                literal = left.value
                if not _SQL_KEYWORDS.search(literal):
                    continue
                right = n.right
                if isinstance(right, (ast.Tuple, ast.List)):
                    args = right.elts
                else:
                    args = [right]
                if not args:
                    continue
                if all(isinstance(a, ast.Constant) for a in args):
                    continue
                slot_names = [_sql_slot_name(a) for a in args]
                if all(name and name.lower() in _SQL_SAFE_INTERPOLATION_NAMES
                       for name in slot_names):
                    continue
                yield _emit("percent_sql", n, literal, slot_names)
                continue

        # ─── V3: "...".format(var, ...) ─────────────────────
        if (isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr in ("format", "format_map")
                and isinstance(n.func.value, ast.Constant)
                and isinstance(n.func.value.value, str)):
            literal = n.func.value.value
            if not _SQL_KEYWORDS.search(literal):
                continue
            args = list(n.args) + [kw.value for kw in n.keywords]
            if not args:
                continue
            if all(isinstance(a, ast.Constant) for a in args):
                continue
            slot_names = [_sql_slot_name(a) for a in args]
            if slot_names and all(name and name.lower() in _SQL_SAFE_INTERPOLATION_NAMES
                                   for name in slot_names):
                continue
            yield _emit("format_sql", n, literal, slot_names)
            continue

        # ─── V4: "SELECT ..." + var  (recursive add chains) ─
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            # collect all string operands in the addition chain
            def _flatten_add(node):
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                    yield from _flatten_add(node.left)
                    yield from _flatten_add(node.right)
                else:
                    yield node
            parts = list(_flatten_add(n))
            str_parts = [p.value for p in parts
                         if isinstance(p, ast.Constant) and isinstance(p.value, str)]
            if not str_parts:
                continue
            combined = " ".join(str_parts)
            if not _SQL_KEYWORDS.search(combined):
                continue
            var_parts = [p for p in parts if not isinstance(p, ast.Constant)]
            if not var_parts:
                continue
            slot_names = [_sql_slot_name(v) for v in var_parts]
            if all(name and name.lower() in _SQL_SAFE_INTERPOLATION_NAMES
                   for name in slot_names):
                continue
            # Only fire on the topmost BinOp of a chain to avoid duplicates
            # (parent walk order will visit the outermost first)
            yield _emit("concat_sql", n, combined, slot_names)


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
    """Flag a loop only if it has RETRY SEMANTICS, not just try/except inside.

    Real retry patterns satisfy at least one of:
      (R1) loop iterates over `range(N)` or `range(0, N)` — a counter, not data
      (R2) `while` condition references an identifier named `retries`/`attempts`/`tries`
      (R3) the except handler contains `continue` (bare retry-and-continue pattern)
    AND the loop body does NOT contain time.sleep / asyncio.sleep / trio.sleep.

    Iterating a list/dict/generator with a try/except is NORMAL per-item
    error handling and MUST NOT fire (was the MobeFace false positive).
    """
    _RETRY_IDENT = ("retries", "retry", "attempts", "attempt", "tries")

    def _loop_is_counter(loop):
        # for _ in range(N)
        if isinstance(loop, ast.For) and isinstance(loop.iter, ast.Call):
            iter_name = _attr_dotted(loop.iter.func) or (
                loop.iter.func.id if isinstance(loop.iter.func, ast.Name) else ""
            )
            return iter_name == "range"
        # while <expr containing 'retries'>
        if isinstance(loop, ast.While):
            for n in ast.walk(loop.test):
                if isinstance(n, ast.Name) and n.id.lower() in _RETRY_IDENT:
                    return True
        return False

    def _except_has_continue(loop):
        for n in ast.walk(loop):
            if isinstance(n, ast.Try):
                for h in n.handlers:
                    for b in h.body:
                        if isinstance(b, ast.Continue):
                            return True
        return False

    def _has_sleep(loop):
        for n in ast.walk(loop):
            if isinstance(n, ast.Call):
                target = _attr_dotted(n.func)
                if target in ("time.sleep", "asyncio.sleep", "trio.sleep"):
                    return True
        return False

    def _has_try(loop):
        return any(isinstance(n, ast.Try) for n in ast.walk(loop))

    for loop in ast.walk(tree):
        if not isinstance(loop, (ast.For, ast.While)):
            continue
        if not _has_try(loop):
            continue
        if _has_sleep(loop):
            continue

        # RULE: only counter-based (range or retry-named while) loops count as
        # retry patterns. Iterating a collection with try/except/continue is
        # per-item error handling, NOT a retry — must not fire.
        if not _loop_is_counter(loop):
            continue

        # Additionally require an actual retry action inside the except handler:
        # either `continue` (bare retry) or a call in the try body that is
        # re-attempted. Bare `pass` in except of a counter loop is unusual but
        # counts as retry (the loop keeps hammering).
        if not _except_has_continue(loop):
            # allow bare `except: pass` inside a range loop as retry too
            has_pass_handler = False
            for n in ast.walk(loop):
                if isinstance(n, ast.ExceptHandler):
                    body = n.body
                    if body and len(body) == 1 and isinstance(body[0], ast.Pass):
                        has_pass_handler = True
                        break
            if not has_pass_handler:
                continue

        yield {
            "line": loop.lineno,
            "evidence": "counter-based retry loop with no backoff sleep",
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
# SIX NEW SECURITY SYNDROMES (v4.1)
# ══════════════════════════════════════════════════════════════════

_SECRET_VAR_NAMES = {
    "api_key", "apikey", "secret_key", "secret", "password", "passwd",
    "token", "access_key", "access_token", "private_key", "auth_token",
    "bearer_token", "client_secret",
}
_SECRET_VALUE_RE = re.compile(
    r"(?:^(sk-|AKIA|AIza|ghp_|xox[baprs]-)[A-Za-z0-9_\-]{10,}|"
    r"^[A-Za-z0-9_\-/+]{24,}$)"
)
_REGEX_DOS_RE = re.compile(r"\([^)]*[+*]\)[+*]|\([^)]*\+[^)]*\)\+|\(\.\+\)\+|\(\.\*\)\*")
_DANGEROUS_DESERIALIZERS = {
    "pickle.loads", "pickle.load",
    "cPickle.loads", "cPickle.load",
    "marshal.loads", "marshal.load",
    "shelve.open",
}


@register_syndrome(
    "Weak_Crypto",
    severity="HIGH",
    description="Use of broken cryptographic hash functions (MD5/SHA1).",
    confession="I confessed at line {line}: I trusted MD5 or SHA1 to keep my secrets. "
               "Both have been broken for over a decade. What was I protecting?",
)
def _weak_crypto(tree):
    weak_names = {"md5", "sha1"}
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        target = _attr_dotted(n.func) or (n.func.id if isinstance(n.func, ast.Name) else "")
        if target in {"hashlib.md5", "hashlib.sha1"}:
            yield {
                "line": n.lineno,
                "evidence": f"{target}()",
                "predicate": {"kind": "weak_hash", "line": n.lineno, "algo": target.split(".")[-1]},
                "adversary": "forge a collision to bypass integrity checks",
            }
        elif isinstance(n.func, ast.Attribute) and n.func.attr == "new":
            # Crypto.Hash.MD5.new() / Cryptodome.Hash.SHA1.new()
            parent = _attr_dotted(n.func.value)
            if parent and any(w in parent for w in ("MD5", "SHA1")):
                yield {
                    "line": n.lineno,
                    "evidence": f"{parent}.new()",
                    "predicate": {"kind": "weak_hash", "line": n.lineno, "algo": parent},
                    "adversary": "forge a collision to bypass integrity checks",
                }


@register_syndrome(
    "Hardcoded_Secret",
    severity="CRITICAL",
    description="API key / password / token assigned as a string literal in source.",
    confession="I confessed at line {line}: I hardcoded a secret in the source. "
               "Every commit, every clone, every fork carries it forward.",
)
def _hardcoded_secret(tree):
    for n in ast.walk(tree):
        if not isinstance(n, ast.Assign):
            continue
        if not (isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)):
            continue
        literal = n.value.value
        if not _SECRET_VALUE_RE.search(literal):
            continue
        for target in n.targets:
            name = None
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            if name and name.lower() in _SECRET_VAR_NAMES:
                yield {
                    "line": n.lineno,
                    "evidence": f"{name} = <redacted:{len(literal)}-char string>",
                    "predicate": {"kind": "hardcoded_secret", "line": n.lineno, "var": name},
                    "adversary": "grep the repo history — the key is there in every clone",
                }
                break


@register_syndrome(
    "Regex_DoS",
    severity="MEDIUM",
    description="Regex with catastrophic backtracking patterns (nested unbounded quantifiers).",
    confession="I confessed at line {line}: My regex has nested quantifiers. "
               "One adversarial input turns me into a CPU heater.",
)
def _regex_dos(tree):
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        target = _attr_dotted(n.func)
        if target not in ("re.compile", "re.match", "re.search",
                          "re.sub", "re.findall", "re.finditer", "re.fullmatch"):
            continue
        if not n.args:
            continue
        first = n.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            continue
        pattern = first.value
        if _REGEX_DOS_RE.search(pattern):
            yield {
                "line": n.lineno,
                "evidence": f"catastrophic pattern in {target}: {pattern[:80]!r}",
                "predicate": {"kind": "regex_dos", "line": n.lineno, "pattern": pattern[:200]},
                "adversary": "feed a string like 'aaaaaaaaaa!' — backtracking explodes",
            }


@register_syndrome(
    "Path_Traversal",
    severity="HIGH",
    description="open() with a dynamic path derived from external input — no sandbox.",
    confession="I confessed at line {line}: I open whatever path the caller hands me. "
               "'../../etc/passwd' is a valid path to me.",
)
def _path_traversal(tree):
    def _is_external_source(node):
        # sys.argv[i], request.args.get(...), request.form[...], os.environ[...]
        if isinstance(node, ast.Subscript):
            base = _attr_dotted(node.value)
            if base in ("sys.argv", "os.environ"):
                return True
            if isinstance(node.value, ast.Attribute) and node.value.attr in ("args", "form", "json", "params"):
                return True
        if isinstance(node, ast.Call):
            target = _attr_dotted(node.func)
            if target in ("input", "sys.stdin.readline",
                          "request.args.get", "request.form.get",
                          "request.json.get", "request.values.get"):
                return True
        if isinstance(node, ast.Attribute):
            base = _attr_dotted(node)
            if base and base.startswith("request."):
                return True
        return False

    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"):
            continue
        if not n.args:
            continue
        arg = n.args[0]
        if isinstance(arg, ast.Constant):
            continue  # hardcoded path — safe
        # any Name / Subscript / Attribute / Call from external source
        risky = (
            isinstance(arg, ast.Name)
            or _is_external_source(arg)
            or (isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add))
        )
        if risky:
            yield {
                "line": n.lineno,
                "evidence": "open() called with a non-constant path",
                "predicate": {"kind": "path_traversal", "line": n.lineno},
                "adversary": "pass ../../etc/passwd or ..\\..\\Windows\\win.ini",
            }


@register_syndrome(
    "Insecure_Deserialization",
    severity="CRITICAL",
    description="pickle/marshal/yaml.load/eval/exec on untrusted data — arbitrary code execution.",
    confession="I confessed at line {line}: I deserialize bytes I did not create. "
               "Anyone who controls the input controls the process.",
)
def _insecure_deserialization(tree):
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        # eval / exec with a non-constant argument
        if isinstance(n.func, ast.Name) and n.func.id in ("eval", "exec"):
            if n.args and not (isinstance(n.args[0], ast.Constant)
                               and isinstance(n.args[0].value, str)):
                yield {
                    "line": n.lineno,
                    "evidence": f"{n.func.id}() on dynamic argument",
                    "predicate": {"kind": "eval_exec", "line": n.lineno, "fn": n.func.id},
                    "adversary": "pass '__import__(\"os\").system(\"id\")'",
                }
                continue
        target = _attr_dotted(n.func)
        if target in _DANGEROUS_DESERIALIZERS:
            yield {
                "line": n.lineno,
                "evidence": f"{target}() on untrusted bytes",
                "predicate": {"kind": "unsafe_deserialize", "line": n.lineno, "fn": target},
                "adversary": "craft a pickle payload that runs os.system('id') on load",
            }
            continue
        # yaml.load without SafeLoader
        if target == "yaml.load":
            has_safe_loader = False
            for kw in n.keywords:
                if kw.arg == "Loader":
                    loader = _attr_dotted(kw.value) or (
                        kw.value.id if isinstance(kw.value, ast.Name) else "")
                    if "Safe" in loader:
                        has_safe_loader = True
                        break
            if not has_safe_loader:
                yield {
                    "line": n.lineno,
                    "evidence": "yaml.load() without Loader=SafeLoader",
                    "predicate": {"kind": "unsafe_deserialize", "line": n.lineno, "fn": "yaml.load"},
                    "adversary": "craft a YAML payload with !!python/object/apply:os.system",
                }


@register_syndrome(
    "Race_Condition",
    severity="MEDIUM",
    description="TOCTOU: os.path.exists(p) followed by open(p) — attacker can swap the path between checks.",
    confession="I confessed at line {line}: I checked the path, then opened it. "
               "In the gap between check and use, anything can happen.",
)
def _race_condition(tree):
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        # Find every os.path.exists(X) call and its argument identifier
        check_calls: dict[str, int] = {}   # arg identifier → line
        for c in ast.walk(fn):
            if not (isinstance(c, ast.Call) and _attr_dotted(c.func) == "os.path.exists"):
                continue
            if not c.args:
                continue
            arg = c.args[0]
            if isinstance(arg, ast.Name):
                check_calls[arg.id] = c.lineno
        # Look for subsequent open(same_name) that isn't inside a try
        for u in ast.walk(fn):
            if not (isinstance(u, ast.Call) and isinstance(u.func, ast.Name)
                    and u.func.id == "open"):
                continue
            if not u.args or not isinstance(u.args[0], ast.Name):
                continue
            name = u.args[0].id
            if name not in check_calls:
                continue
            if u.lineno <= check_calls[name]:
                continue
            # inside a try? (simple ancestor check)
            in_try = False
            for parent in ast.walk(fn):
                if isinstance(parent, ast.Try):
                    for child in ast.walk(parent):
                        if child is u:
                            in_try = True
                            break
                    if in_try:
                        break
            if not in_try:
                yield {
                    "line": u.lineno,
                    "evidence": f"os.path.exists({name}) at line {check_calls[name]} "
                                f"followed by open({name}) at line {u.lineno}",
                    "predicate": {"kind": "toctou", "line": u.lineno,
                                  "check_line": check_calls[name], "var": name},
                    "adversary": "in the microsecond between check and open, replace the file with a symlink",
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
