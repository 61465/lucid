"""
Mutation Gate — trial by execution.

Consumes an Assumption, synthesizes the adversarial call that would violate it,
runs the harness in the existing sandbox, and returns a GateResult with a clean
survives/dies/inconclusive verdict.

Design principles (from spike):
    1. Structured Assumption, never free text. Adversarial dispatch is a lookup.
    2. Only assumptions on function ARGS are testable (others are extractor bugs).
    3. Network assumptions target a guaranteed-unreachable local port so no real
       host is touched. Filesystem assumptions target a guaranteed-nonexistent
       path. All I/O adversaries stay inside the sandbox.
    4. Timeout is intentional: if the code hangs on adversarial input, that IS
       the confirmation ("assumption was load-bearing").
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from lucidcode.sandbox import run_sandboxed
from .assumptions import Assumption, AssumptionKind

Verdict = Literal["survives", "dies", "inconclusive"]


@dataclass
class GateResult:
    verdict: Verdict
    reason: str
    latency_ms: int = 0
    stdout: str = ""
    stderr: str = ""

    @property
    def confession_confirmed(self) -> bool:
        return self.verdict == "survives"


# ─────────────────────────────────────────────────────────────
# adversarial-value bank (per kind)
# ─────────────────────────────────────────────────────────────
_ADVERSARY_LITERAL = {
    "not_zero":          "0",
    "not_none":          "None",
    "not_empty":         '""',
    "network_reachable": '"http://127.0.0.1:1"',   # guaranteed closed port
    "file_exists":       '"/nonexistent/lucidcode/therapy/xyz"',
    "key_exists":        "{}",                     # empty dict — key absent
}


def _adversarial_args(kind: AssumptionKind, target: str,
                       arg_positions: list[str]) -> str:
    parts = []
    for name in arg_positions:
        if name == target:
            parts.append(_ADVERSARY_LITERAL[kind])
        else:
            parts.append("1")
    return ", ".join(parts)


def _extract_arg_names(source: str, function_name: str) -> list[str]:
    import ast
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            return [a.arg for a in node.args.args]
    return []


def _isolate_function(source: str, function_name: str) -> str | None:
    """Extract JUST the target function definition as a runnable snippet.

    Real project files have imports of packages we don't have in the sandbox
    (requests, sqlite3, custom modules). Running the full file crashes on
    import. Instead we lift the single function body and stub every free name
    it references. This lets us test the function's LOGIC in isolation.

    Returns None if the function can't be safely isolated (e.g., decorators
    with dynamic behavior, closures over module-level state we can't stub).
    """
    import ast
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    fn_node = None
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == function_name:
            fn_node = n
            break
    if fn_node is None:
        return None

    # collect free names used inside the function body that aren't the args
    # themselves — every one gets stubbed.
    arg_names = {a.arg for a in fn_node.args.args}
    used_names: set[str] = set()
    assigned_names: set[str] = set()
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Name):
            if isinstance(n.ctx, ast.Load):
                used_names.add(n.id)
            elif isinstance(n.ctx, (ast.Store, ast.Del)):
                assigned_names.add(n.id)
    free = used_names - arg_names - assigned_names - _BUILTIN_NAMES

    # dotted names via Attribute — stub the ROOT
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Attribute):
            root = n
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                free.add(root.id)
    free -= _BUILTIN_NAMES
    free -= arg_names
    free -= assigned_names

    stub_lines = ["# lucidcode isolation stubs"]
    for name in sorted(free):
        # any-attribute, any-call stub
        stub_lines.append(
            f"class _S_{name}:\n"
            f"    def __getattr__(self, _): return _S_{name}()\n"
            f"    def __call__(self, *a, **k): return _S_{name}()\n"
            f"    def __getitem__(self, _): return _S_{name}()\n"
            f"    def __iter__(self): return iter([])\n"
            f"    def __bool__(self): return True\n"
            f"{name} = _S_{name}()\n"
        )

    try:
        fn_src = ast.unparse(fn_node) if hasattr(ast, "unparse") else None
    except Exception:
        return None
    if not fn_src:
        return None

    return "\n".join(stub_lines) + "\n\n" + fn_src + "\n"


_BUILTIN_NAMES = {
    "print", "len", "range", "int", "str", "list", "dict", "set", "tuple",
    "bool", "float", "type", "isinstance", "hasattr", "getattr", "setattr",
    "None", "True", "False", "open", "input", "abs", "min", "max", "sum",
    "sorted", "reversed", "enumerate", "zip", "map", "filter", "any", "all",
    "iter", "next", "repr", "chr", "ord", "hex", "oct", "bin",
    "Exception", "ValueError", "TypeError", "KeyError", "IndexError",
    "AttributeError", "RuntimeError", "OSError", "IOError", "FileNotFoundError",
    "BaseException", "StopIteration", "self", "cls",
}


# ─────────────────────────────────────────────────────────────
# the gate
# ─────────────────────────────────────────────────────────────
def test_assumption(source: str, assumption: Assumption,
                    timeout: int = 4) -> GateResult:
    args = _extract_arg_names(source, assumption.function)
    if not args:
        return GateResult(
            verdict="inconclusive",
            reason=f"function `{assumption.function}` not found",
        )
    if assumption.target not in args:
        return GateResult(
            verdict="inconclusive",
            reason=f"target `{assumption.target}` not a function arg",
        )
    if assumption.kind not in _ADVERSARY_LITERAL:
        return GateResult(
            verdict="inconclusive",
            reason=f"no adversarial literal registered for kind `{assumption.kind}`",
        )

    isolated = _isolate_function(source, assumption.function)
    if isolated is None:
        return GateResult(
            verdict="inconclusive",
            reason=f"could not isolate `{assumption.function}` for standalone execution",
        )

    call = _adversarial_args(assumption.kind, assumption.target, args)
    harness = isolated + (
        "\n"
        "try:\n"
        f"    _r = {assumption.function}({call})\n"
        "    print('SAFE:', repr(_r)[:80])\n"
        "except BaseException as _e:\n"
        "    print('VULN_TRIGGERED:', type(_e).__name__, repr(str(_e))[:80])\n"
    )

    result = run_sandboxed(harness, timeout=timeout, mode="subprocess")

    if result.verdict == "vuln_triggered":
        return GateResult(
            verdict="survives",
            reason=f"adversarial input broke `{assumption.function}` — confession is real",
            latency_ms=int(result.meta.get("latency_ms", 0)) if result.meta else 0,
            stdout=result.stdout[:300], stderr=result.stderr[:300],
        )
    if result.verdict == "safe":
        return GateResult(
            verdict="dies",
            reason="adversarial input handled cleanly — assumption was guarded",
            stdout=result.stdout[:300], stderr=result.stderr[:300],
        )
    if result.verdict == "timeout":
        return GateResult(
            verdict="survives",
            reason="adversarial input caused a hang — assumption was load-bearing",
            stdout=result.stdout[:300], stderr=result.stderr[:300],
        )
    return GateResult(
        verdict="inconclusive",
        reason=f"sandbox verdict={result.verdict}: {result.detail[:120]}",
        stdout=result.stdout[:300], stderr=result.stderr[:300],
    )
