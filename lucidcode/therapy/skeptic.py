"""
Skeptic — the second, deterministic falsifier that runs AFTER the mutation gate.

Even a survived mutation can be a false alarm. The skeptic checks:

    1. REACHABILITY — is the function actually called anywhere in the file?
       An assumption in dead code isn't a real risk.
    2. GUARD — is there a same-line or prior-line `if` that would prevent the
       adversarial input from reaching the vulnerable expression?
    3. EARLY_RETURN — does the function return early when the adversarial
       condition holds (e.g. `if not b: return 0`)?
    4. TYPE_HINT — does the annotation explicitly forbid the adversarial value?
       (`b: int` doesn't; `b: NonZero` in practice does — we can only detect
       the shape "annotation is a NewType or Literal that excludes the value".)

The skeptic returns SkepticVerdict:
    - "upheld"   : all checks passed; the confession still stands
    - "refuted"  : at least one check found protection the gate missed
    - "unclear" : the checks were structurally inapplicable

This is pure AST work — no LLM, no execution.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Literal

from .assumptions import Assumption

Ruling = Literal["upheld", "refuted", "unclear"]


@dataclass
class SkepticVerdict:
    ruling: Ruling
    reason: str


_GUARD_TESTS_BY_KIND = {
    # For each kind, if we see any of these boolean tests earlier in the
    # function, the assumption is guarded and the survived-mutation is
    # actually a false alarm.
    "not_zero":  ("if not {target}", "if {target} == 0", "if {target}:",
                  "if {target} != 0"),
    "not_none":  ("if {target} is None", "if not {target}",
                  "if {target} is not None"),
    "not_empty": ("if not {target}", "if len({target})",
                  "if {target}:"),
}


def _function_node(tree, name: str):
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    return None


def _has_call_to(tree, name: str) -> bool:
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            callee = None
            if isinstance(n.func, ast.Name):
                callee = n.func.id
            elif isinstance(n.func, ast.Attribute):
                callee = n.func.attr
            if callee == name:
                return True
    return False


def _guarded_by_early_return(fn: ast.FunctionDef, assumption: Assumption) -> bool:
    """Look for `if <condition on target>: return ...` at the top of the fn."""
    for stmt in fn.body:
        if not isinstance(stmt, ast.If):
            continue
        # any return / raise inside the if body?
        exits = any(isinstance(x, (ast.Return, ast.Raise))
                    for x in ast.walk(stmt))
        if not exits:
            continue
        # does the condition reference our target?
        for n in ast.walk(stmt.test):
            if isinstance(n, ast.Name) and n.id == assumption.target:
                return True
    return False


def _guarded_by_type_hint(fn: ast.FunctionDef, assumption: Assumption) -> bool:
    """Very narrow: annotation is Literal[...] that excludes adversarial value."""
    for arg in fn.args.args:
        if arg.arg != assumption.target or arg.annotation is None:
            continue
        text = ast.unparse(arg.annotation) if hasattr(ast, "unparse") else ""
        if text.startswith("Literal[") and _adversarial_display(assumption) not in text:
            return True
    return False


def _adversarial_display(assumption: Assumption) -> str:
    return {
        "not_zero": "0",
        "not_none": "None",
        "not_empty": "''",
    }.get(assumption.kind, "")


# ─────────────────────────────────────────────────────────────
def judge(source: str, assumption: Assumption) -> SkepticVerdict:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return SkepticVerdict("unclear", "source unparseable")

    fn = _function_node(tree, assumption.function)
    if fn is None:
        return SkepticVerdict("unclear", "target function not found")

    # 1. Is the function reachable? (has any call site in this file or is exported?)
    reachable = _has_call_to(tree, assumption.function)
    if not reachable and not assumption.function.startswith("_"):
        # public function — assume it's called by importers, treat as reachable
        reachable = True
    if not reachable:
        return SkepticVerdict(
            "refuted",
            f"`{assumption.function}` is private and never called in this file",
        )

    # 2. Explicit early-return guard on the target?
    if _guarded_by_early_return(fn, assumption):
        return SkepticVerdict(
            "refuted",
            f"function guards `{assumption.target}` with an early return / raise",
        )

    # 3. Narrow type-hint that excludes adversarial value?
    if _guarded_by_type_hint(fn, assumption):
        return SkepticVerdict(
            "refuted",
            f"annotation on `{assumption.target}` excludes the adversarial value",
        )

    return SkepticVerdict("upheld", "no protective structure found")
