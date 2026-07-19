"""
Regression harness for LucidCode syndromes.

Each fixture in `fixtures/` is a Python file plus a `.expected.json`.
Format of `.expected.json`:

    {
      "fixture": "sqli_positive.py",
      "syndrome": "Blind_Trust_SQLi",
      "expect": [
        {"line": 3, "should_detect": true}
      ]
    }

Metric outputs are aggregated into REPORT.md at the end of the test session.
"""
from __future__ import annotations

import json
from pathlib import Path
from collections import defaultdict

import pytest

from lucidcode.syndromes import detect_all
from tests.regression._metrics import record_metric

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixtures():
    if not FIXTURES_DIR.exists():
        return []
    out = []
    for py in sorted(FIXTURES_DIR.glob("*.py")):
        exp = py.with_suffix(".expected.json")
        if not exp.exists():
            continue
        out.append((py, json.loads(exp.read_text(encoding="utf-8"))))
    return out


_FIXTURES = _load_fixtures()


@pytest.mark.parametrize("py_path,expected", _FIXTURES,
                         ids=[p.stem for p, _ in _FIXTURES])
def test_fixture(py_path: Path, expected: dict):
    source = py_path.read_text(encoding="utf-8")
    hits = detect_all(source)
    hits_by_syndrome_line = {(h["syndrome"], h["line"]) for h in hits}

    syndrome = expected["syndrome"]
    for case in expected["expect"]:
        line = case["line"]
        should = case["should_detect"]
        detected = (syndrome, line) in hits_by_syndrome_line
        if should and detected:
            record_metric(syndrome, "tp")
        elif should and not detected:
            record_metric(syndrome, "fn")
            pytest.fail(f"{py_path.name}: expected {syndrome} at line {line}, got none")
        elif not should and detected:
            record_metric(syndrome, "fp")
            pytest.fail(f"{py_path.name}: false positive — {syndrome} at line {line}")
