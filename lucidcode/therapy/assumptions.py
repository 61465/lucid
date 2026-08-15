"""
Assumption extraction — the first invariant.

Walks the AST of a function and yields structured Assumption records for every
place the function relies on the world being a certain way. Deterministic. No
LLM. This is the ground layer of "what could the code confess?"

Each Assumption is tied to:
    - kind      : one of the tested vocabulary the mutation gate can violate
    - target    : the identifier the assumption is about (must be a function arg
                  so the gate can inject an adversarial value positionally)
    - function  : function name (needed for the gate to construct a call)
    - line      : the exact source line the assumption lives on
    - snippet   : verbatim source line (token provenance — the confession will
                  only use words that appear here)

Only assumptions targeting function ARGUMENTS survive the extractor. Assumptions
on intermediate variables can't be tested by the gate without full symbolic
execution, so we discard them by construction rather than paper over them.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Literal, Iterable

AssumptionKind = Literal[
    "not_zero",
    "not_none",
    "not_empty",
    "network_reachable",
    "file_exists",
    "key_exists",
]


@dataclass
class Assumption:
    kind: AssumptionKind
    target: str
    function: str
    line: int
    snippet: str = ""
    metadata: dict = field(default_factory=dict)

    def as_confession(self) -> str:
        m = {
            "not_zero":          f"I assumed `{self.target}` is never zero",
            "not_none":          f"I assumed `{self.target}` is never None",
            "not_empty":         f"I assumed `{self.target}` is never empty",
            "network_reachable": f"I assumed the network at `{self.target}` always answers",
            "file_exists":       f"I assumed the path at `{self.target}` always exists",
            "key_exists":        f"I assumed the key from `{self.target}` is always present",
        }
        return m[self.kind]


# ─────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────
def _attr_dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.insert(0, node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.insert(0, node.id)
        return ".".join(parts)
    return ""


def _source_line(source_lines: list[str], lineno: int) -> str:
    if 1 <= lineno <= len(source_lines):
        return source_lines[lineno - 1].strip()
    return ""


# ─────────────────────────────────────────────────────────────
# per-kind extractors — each yields Assumptions bound to args only
# ─────────────────────────────────────────────────────────────
_NETWORK_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.head", "requests.patch", "requests.request",
    "httpx.get", "httpx.post", "httpx.request",
    "urllib.request.urlopen",
}


def _extract_from_function(fn: ast.FunctionDef, source_lines: list[str]) -> Iterable[Assumption]:
    args = {a.arg for a in fn.args.args}
    if not args:
        return

    # not_zero — arg used as divisor in / // %
    for n in ast.walk(fn):
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            if isinstance(n.right, ast.Name) and n.right.id in args:
                yield Assumption(
                    kind="not_zero", target=n.right.id, function=fn.name,
                    line=n.lineno, snippet=_source_line(source_lines, n.lineno),
                )

    # not_none — arg.something, arg[..], arg()
    for n in ast.walk(fn):
        base = None
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
            base = n.value.id
        elif isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name):
            base = n.value.id
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
            base = n.func.id
        if base and base in args:
            yield Assumption(
                kind="not_none", target=base, function=fn.name,
                line=n.lineno, snippet=_source_line(source_lines, n.lineno),
            )

    # not_empty — arg[0] specifically, or len(arg) > 0 patterns
    for n in ast.walk(fn):
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id in args:
            if isinstance(n.slice, ast.Constant) and n.slice.value == 0:
                yield Assumption(
                    kind="not_empty", target=n.value.id, function=fn.name,
                    line=n.lineno, snippet=_source_line(source_lines, n.lineno),
                )

    # network_reachable — arg passed as first positional to known network calls
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        callee = _attr_dotted(n.func)
        if callee not in _NETWORK_CALLS:
            continue
        if not n.args:
            continue
        first = n.args[0]
        if isinstance(first, ast.Name) and first.id in args:
            yield Assumption(
                kind="network_reachable", target=first.id, function=fn.name,
                line=n.lineno, snippet=_source_line(source_lines, n.lineno),
                metadata={"callee": callee},
            )

    # file_exists — arg passed as first positional to open()
    for n in ast.walk(fn):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "open"):
            continue
        if not n.args:
            continue
        first = n.args[0]
        if isinstance(first, ast.Name) and first.id in args:
            yield Assumption(
                kind="file_exists", target=first.id, function=fn.name,
                line=n.lineno, snippet=_source_line(source_lines, n.lineno),
            )

    # key_exists — arg[str_const] or arg.get(str_const)
    for n in ast.walk(fn):
        if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id in args:
            if isinstance(n.slice, ast.Constant) and isinstance(n.slice.value, str):
                yield Assumption(
                    kind="key_exists", target=n.value.id, function=fn.name,
                    line=n.lineno, snippet=_source_line(source_lines, n.lineno),
                    metadata={"key": n.slice.value},
                )


# ─────────────────────────────────────────────────────────────
# public
# ─────────────────────────────────────────────────────────────
def extract_assumptions(source: str) -> list[Assumption]:
    """Return every candidate assumption in `source` bound to a function arg."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    out: list[Assumption] = []
    seen: set = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for a in _extract_from_function(node, lines):
            key = (a.kind, a.target, a.function, a.line)
            if key in seen:
                continue
            seen.add(key)
            out.append(a)
    return out


if __name__ == "__main__":
    demo = (
        "import requests\n"
        "def divide(a, b):\n"
        "    return a / b\n"
        "def first(items):\n"
        "    return items[0]\n"
        "def fetch(url):\n"
        "    return requests.get(url).status_code\n"
        "def read(path):\n"
        "    return open(path).read()\n"
        "def lookup(data):\n"
        "    return data['id']\n"
        "def poke(user):\n"
        "    return user.name\n"
    )
    for a in extract_assumptions(demo):
        print(f"  [{a.kind:20s}] {a.function}({a.target}) @ line {a.line}")
        print(f"      → {a.as_confession()}")
