"""
LucidCode CLI — `lucid analyze` for terminal, CI, and IDE integration.

Commands:
    lucid analyze PATH                 # human-readable output
    lucid analyze PATH --json          # JSON to stdout
    lucid analyze PATH --sarif OUT     # SARIF 2.1.0 file
    lucid analyze PATH --min-verdict LIKELY
    lucid analyze PATH --no-color
    lucid analyze --stdin              # read from stdin
    lucid syndromes                    # list all registered syndromes
    lucid version

Exit codes:
    0 = no TRUTH/LIKELY findings   (safe to merge)
    1 = at least one finding       (CI gate should block)
    2 = usage error
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

try:
    import click
except ImportError:
    print("[lucid] `click` not installed. Run: pip install click", file=sys.stderr)
    sys.exit(2)

from lucidcode.pipeline import analyze, AnalysisResult
from lucidcode.core.trauma import Verdict, ValidatedTrauma
from lucidcode.syndromes import SYNDROMES


__version__ = "0.4.0"

# ─── colors ─────────────────────────────────────────────
_ANSI_GOLD   = "\033[38;5;220m"
_ANSI_YELLOW = "\033[38;5;226m"
_ANSI_ORANGE = "\033[38;5;208m"
_ANSI_RED    = "\033[38;5;196m"
_ANSI_DIM    = "\033[38;5;244m"
_ANSI_RESET  = "\033[0m"

_COLOR_BY_VERDICT = {
    Verdict.TRUTH:         _ANSI_GOLD,
    Verdict.LIKELY:        _ANSI_YELLOW,
    Verdict.DISPUTED:      _ANSI_ORANGE,
    Verdict.HALLUCINATION: _ANSI_RED,
}
_VERDICT_ORDER = {v: i for i, v in enumerate(
    [Verdict.HALLUCINATION, Verdict.DISPUTED, Verdict.LIKELY, Verdict.TRUTH]
)}
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error",
                "MEDIUM": "warning", "LOW": "note"}
_SKIP_DIRS = {".venv", ".git", "__pycache__", "node_modules", "dist", "build"}


def _color(text: str, code: str, enable: bool) -> str:
    return f"{code}{text}{_ANSI_RESET}" if enable else text


def _walk_py_files(root: Path):
    if root.is_file():
        if root.suffix == ".py":
            yield root
        return
    for p in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        yield p


def _analyze_target(path: Path | None, stdin: bool) -> list[tuple[Path, AnalysisResult]]:
    if stdin:
        src = sys.stdin.read()
        return [(Path("<stdin>"), analyze(src))]
    if not path:
        raise click.UsageError("provide a PATH or use --stdin")
    if not path.exists():
        raise click.UsageError(f"path does not exist: {path}")
    results = []
    for py in _walk_py_files(path):
        try:
            src = py.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            click.echo(f"[skip] {py}: {e}", err=True)
            continue
        results.append((py, analyze(src)))
    return results


def _filter_by_verdict(shown: list[ValidatedTrauma], min_v: Verdict) -> list[ValidatedTrauma]:
    threshold = _VERDICT_ORDER[min_v]
    return [v for v in shown if _VERDICT_ORDER[v.verdict] >= threshold]


# ─── output renderers ──────────────────────────────────────
def _render_human(pairs, min_v: Verdict, use_color: bool) -> tuple[str, int]:
    lines: list[str] = []
    findings = 0
    for path, r in pairs:
        header = f"── {path} ──"
        lines.append(_color(header, _ANSI_DIM, use_color))
        if not r.ok:
            lines.append(f"  [SHIELD] rejected: {r.shield_reason}")
            continue
        picks = _filter_by_verdict(r.shown, min_v)
        findings += len(picks)
        if not picks:
            lines.append(_color("  clean", _ANSI_DIM, use_color))
            continue
        for v in picks:
            c = _COLOR_BY_VERDICT[v.verdict]
            badge = _color(f"[{v.verdict.value}]", c, use_color)
            score = f"posterior={v.posterior_probability:.2f}"
            lines.append(f"  {badge} {v.trauma.syndrome:22s} line {v.trauma.line:3d}  {score}  driver={v.dominant_evidence}")
            conf = (v.trauma.confession or v.trauma.evidence)[:200]
            lines.append(_color(f"      {conf}", _ANSI_DIM, use_color))
    lines.append("")
    lines.append(f"total findings ≥ {min_v.value}: {findings}")
    return "\n".join(lines), findings


def _render_json(pairs, min_v: Verdict) -> tuple[str, int]:
    out = []
    findings = 0
    for path, r in pairs:
        picks = _filter_by_verdict(r.shown, min_v) if r.ok else []
        findings += len(picks)
        out.append({
            "path": str(path),
            "ok": r.ok,
            "shield_reason": r.shield_reason,
            "traumas_detected": r.traumas_detected,
            "latency_ms": r.latency_ms,
            "findings": [v.to_dict() for v in picks],
        })
    return json.dumps(out, indent=2, ensure_ascii=False), findings


def _render_sarif(pairs, min_v: Verdict) -> tuple[str, int]:
    results = []
    rules_seen: dict[str, dict] = {}
    findings = 0
    for path, r in pairs:
        if not r.ok:
            continue
        for v in _filter_by_verdict(r.shown, min_v):
            findings += 1
            t = v.trauma
            rules_seen.setdefault(t.syndrome, {
                "id": t.syndrome,
                "name": t.syndrome,
                "shortDescription": {"text": SYNDROMES[t.syndrome].description
                                     if t.syndrome in SYNDROMES else t.syndrome},
                "defaultConfiguration": {
                    "level": _SARIF_LEVEL.get(t.severity, "warning"),
                },
            })
            results.append({
                "ruleId": t.syndrome,
                "level": _SARIF_LEVEL.get(t.severity, "warning"),
                "message": {"text": (t.confession or t.evidence)[:600]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": str(path).replace("\\", "/")},
                        "region": {"startLine": max(1, t.line)},
                    },
                }],
                "properties": {
                    "verdict": v.verdict.value,
                    "posterior_probability": round(v.posterior_probability, 4),
                    "dominant_evidence": v.dominant_evidence,
                },
            })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "LucidCode",
                "version": __version__,
                "informationUri": "https://lucidcode.dev",
                "rules": list(rules_seen.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False), findings


# ─── click entrypoint ──────────────────────────────────────
@click.group()
def cli():
    """LucidCode — code confesses its missing needs."""


@cli.command(name="analyze")
@click.argument("path", type=click.Path(path_type=Path), required=False)
@click.option("--stdin", "read_stdin", is_flag=True, help="read source from stdin")
@click.option("--json", "out_json", is_flag=True, help="emit JSON to stdout")
@click.option("--sarif", "sarif_out", type=click.Path(path_type=Path), default=None,
              help="write SARIF 2.1.0 report to file")
@click.option("--min-verdict", type=click.Choice(["TRUTH", "LIKELY", "DISPUTED"]),
              default="LIKELY", show_default=True)
@click.option("--no-color", is_flag=True, help="disable ANSI colors")
def analyze_cmd(path, read_stdin, out_json, sarif_out, min_verdict, no_color):
    """Analyze a file, directory, or stdin."""
    pairs = _analyze_target(path, read_stdin)
    min_v = Verdict(min_verdict)
    use_color = (not no_color) and sys.stdout.isatty() and os.name != "nt"  # honest on Win

    if sarif_out:
        content, findings = _render_sarif(pairs, min_v)
        sarif_out.write_text(content, encoding="utf-8")
        click.echo(f"[lucid] wrote SARIF → {sarif_out} ({findings} findings)")
    elif out_json:
        content, findings = _render_json(pairs, min_v)
        click.echo(content)
    else:
        content, findings = _render_human(pairs, min_v, use_color)
        click.echo(content)

    sys.exit(1 if findings > 0 else 0)


@cli.command()
def syndromes():
    """List all registered syndromes."""
    for name, s in SYNDROMES.items():
        click.echo(f"  {s.severity.value:8s}  {name:22s}  {s.description}")


@cli.command()
def version():
    """Show LucidCode version."""
    click.echo(f"LucidCode {__version__} · {len(SYNDROMES)} syndromes registered")


if __name__ == "__main__":
    cli()
