"""Pytest config + report writer for LucidCode regression tests."""
import sys
from pathlib import Path

# ensure package import from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

REPORT_PATH = Path(__file__).parent / "REPORT.md"


def pytest_sessionfinish(session, exitstatus):
    from tests.regression._metrics import METRICS
    if not METRICS:
        REPORT_PATH.write_text("# LucidCode Regression Report\n\n_No metrics recorded._\n",
                               encoding="utf-8")
        return

    from lucidcode.syndromes import SYNDROMES
    lines = [
        "# LucidCode Regression Report",
        "",
        f"Total syndromes registered: **{len(SYNDROMES)}**",
        f"Total fixtures executed:    **{sum(sum(m.values()) for m in METRICS.values())}**",
        "",
        "| Syndrome | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for syn in sorted(METRICS):
        m = METRICS[syn]
        tp, fp, fn = m["tp"], m["fp"], m["fn"]
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        lines.append(f"| {syn} | {tp} | {fp} | {fn} | {prec:.2f} | {rec:.2f} | {f1:.2f} |")

    lines += ["", "_Precision = TP/(TP+FP), Recall = TP/(TP+FN), F1 = harmonic mean._"]
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n[report] wrote {REPORT_PATH}")
