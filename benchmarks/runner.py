"""
Benchmark runner — score LucidCode against CVE-inspired fixtures.

    python -m benchmarks.runner
    python -m benchmarks.runner --json
    python -m benchmarks.runner --markdown > benchmarks/RESULT.md

Metrics:
    TP (true positive)  — expected finding was detected at correct verdict
    FP (false positive) — detection with no matching expectation
    FN (false negative) — expected finding was missed
    Precision = TP / (TP + FP)
    Recall    = TP / (TP + FN)
    F1        = 2·P·R / (P+R)

Also reports:
    - per-syndrome F1
    - clean-code false-positive rate
    - median latency per fixture
    - hallucination-rejection rate (findings with verdict=HALLUCINATION vs shown)
"""
from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict
from typing import Any

from lucidcode.pipeline import analyze
from lucidcode.core.trauma import Verdict
from benchmarks.dataset import BENCH


_VERDICT_ORDER = {v: i for i, v in enumerate(
    [Verdict.HALLUCINATION, Verdict.DISPUTED, Verdict.LIKELY, Verdict.TRUTH]
)}


def _meets(actual: Verdict, minimum: str) -> bool:
    """True if actual verdict is ≥ the required minimum."""
    return _VERDICT_ORDER[actual] >= _VERDICT_ORDER[Verdict(minimum)]


def run() -> dict[str, Any]:
    per_syndrome: dict[str, dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0}
    )
    fixture_reports: list[dict] = []
    latencies: list[int] = []
    clean_fp_hits = 0
    clean_fixtures = 0
    total_shown = 0
    total_rejected = 0

    for b in BENCH:
        expected = [(e["syndrome"], e["line"], e["min_verdict"]) for e in b["expected_findings"]]
        result = analyze(b["source"])
        latencies.append(result.latency_ms)
        total_shown += len(result.shown)
        total_rejected += len(result.rejected)

        # normalize into (syndrome, line, verdict-object) tuples
        actual = [(v.trauma.syndrome, v.trauma.line, v.verdict) for v in result.shown]

        # match each expected against actual
        matched_actual: set[int] = set()
        tp_list, fn_list = [], []
        for exp_syn, exp_line, min_v in expected:
            found_idx = None
            for i, (a_syn, a_line, a_verd) in enumerate(actual):
                if i in matched_actual:
                    continue
                if a_syn == exp_syn and a_line == exp_line and _meets(a_verd, min_v):
                    found_idx = i
                    break
            if found_idx is not None:
                matched_actual.add(found_idx)
                per_syndrome[exp_syn]["tp"] += 1
                tp_list.append((exp_syn, exp_line))
            else:
                per_syndrome[exp_syn]["fn"] += 1
                fn_list.append((exp_syn, exp_line))

        fp_list = []
        for i, (a_syn, a_line, a_verd) in enumerate(actual):
            if i in matched_actual:
                continue
            per_syndrome[a_syn]["fp"] += 1
            fp_list.append((a_syn, a_line, a_verd.value))

        if not expected:
            clean_fixtures += 1
            if actual:
                clean_fp_hits += 1

        fixture_reports.append({
            "name": b["name"],
            "cve": b.get("cve", ""),
            "expected": len(expected),
            "actual": len(actual),
            "tp": len(tp_list),
            "fp": len(fp_list),
            "fn": len(fn_list),
            "latency_ms": result.latency_ms,
            "fp_detail": fp_list[:3],
            "fn_detail": fn_list[:3],
        })

    tp_total = sum(m["tp"] for m in per_syndrome.values())
    fp_total = sum(m["fp"] for m in per_syndrome.values())
    fn_total = sum(m["fn"] for m in per_syndrome.values())

    precision = tp_total / (tp_total + fp_total) if (tp_total + fp_total) else 0.0
    recall    = tp_total / (tp_total + fn_total) if (tp_total + fn_total) else 0.0
    f1        = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0

    per_syn_scored = {}
    for syn, m in per_syndrome.items():
        p = m["tp"] / (m["tp"] + m["fp"]) if (m["tp"] + m["fp"]) else 0.0
        r = m["tp"] / (m["tp"] + m["fn"]) if (m["tp"] + m["fn"]) else 0.0
        s_f1 = (2 * p * r) / (p + r) if (p + r) else 0.0
        per_syn_scored[syn] = {"tp": m["tp"], "fp": m["fp"], "fn": m["fn"],
                               "precision": round(p, 3), "recall": round(r, 3),
                               "f1": round(s_f1, 3)}

    halluc_rejected_rate = (
        total_rejected / (total_shown + total_rejected)
        if (total_shown + total_rejected) else 0.0
    )

    return {
        "fixtures": len(BENCH),
        "totals": {"tp": tp_total, "fp": fp_total, "fn": fn_total},
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "clean_fixtures": clean_fixtures,
        "clean_fp_rate": round(clean_fp_hits / clean_fixtures, 3) if clean_fixtures else 0.0,
        "hallucination_rejection_rate": round(halluc_rejected_rate, 3),
        "median_latency_ms": statistics.median(latencies) if latencies else 0,
        "max_latency_ms": max(latencies) if latencies else 0,
        "per_syndrome": per_syn_scored,
        "per_fixture": fixture_reports,
    }


def render_markdown(r: dict) -> str:
    lines = [
        "# LucidCode Benchmark Report",
        "",
        f"Fixtures scored: **{r['fixtures']}**",
        f"- TP={r['totals']['tp']} FP={r['totals']['fp']} FN={r['totals']['fn']}",
        f"- **Precision**={r['precision']}  **Recall**={r['recall']}  **F1**={r['f1']}",
        f"- Clean-code FP rate: **{r['clean_fp_rate']}** ({r['clean_fixtures']} clean fixtures)",
        f"- Hallucination rejection rate: **{r['hallucination_rejection_rate']}**",
        f"- Median latency: **{r['median_latency_ms']}ms** (max {r['max_latency_ms']}ms)",
        "",
        "## Per-Syndrome",
        "| Syndrome | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for syn in sorted(r["per_syndrome"]):
        m = r["per_syndrome"][syn]
        lines.append(f"| {syn} | {m['tp']} | {m['fp']} | {m['fn']} | {m['precision']} | {m['recall']} | {m['f1']} |")

    lines += ["", "## Per-Fixture", "| Fixture | CVE | Exp | TP | FP | FN | Latency |",
              "|---|---|---:|---:|---:|---:|---:|"]
    for f in r["per_fixture"]:
        lines.append(
            f"| {f['name']} | {f['cve']} | {f['expected']} | {f['tp']} | {f['fp']} | {f['fn']} | {f['latency_ms']}ms |"
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    r = run()
    if "--json" in sys.argv:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    elif "--markdown" in sys.argv:
        print(render_markdown(r))
    else:
        print(f"fixtures={r['fixtures']}  precision={r['precision']}  recall={r['recall']}  f1={r['f1']}")
        print(f"clean_fp_rate={r['clean_fp_rate']}  halluc_reject={r['hallucination_rejection_rate']}")
        print(f"median_latency={r['median_latency_ms']}ms   max={r['max_latency_ms']}ms")
        print()
        print("per-syndrome F1:")
        for syn in sorted(r["per_syndrome"]):
            m = r["per_syndrome"][syn]
            print(f"  {syn:22s} F1={m['f1']}   ({m['tp']}TP {m['fp']}FP {m['fn']}FN)")
