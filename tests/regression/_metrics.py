"""Shared metrics store (importable by both conftest.py and test files)."""
from collections import defaultdict

METRICS: dict = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})


def record_metric(syndrome: str, bucket: str, n: int = 1) -> None:
    METRICS[syndrome][bucket] += n
