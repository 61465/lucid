# Contributing to LucidCode

Thanks for your interest.

## Development setup

```bash
git clone https://github.com/61465/lucid
cd lucid
pip install -e ".[dev]"
```

## Running the test suite

```bash
pytest tests/regression -q       # 15/15 should pass in <1s
python -m benchmarks.runner      # 22-fixture CVE benchmark
```

## Adding a new syndrome

1. Open `lucidcode/syndromes/registry.py`.
2. Add a new `@register_syndrome(...)` block with:
   - A psychiatric-metaphor name (PascalCase).
   - A severity level (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`).
   - A one-line description.
   - A first-person confession template with `{line}` placeholder.
   - A `detect(tree)` generator that yields dicts with `line`, `evidence`, `predicate`, and `adversary`.
3. Add at least one positive and one negative fixture to `tests/regression/fixtures/`.
4. Add at least one CVE-inspired fixture to `benchmarks/dataset.py`.
5. Re-run `pytest tests/regression && python -m benchmarks.runner` and confirm F1 stays ≥ 0.95.

## Adding a new validator engine

1. Subclass `lucidcode.validators.base.Engine` in `lucidcode/validators/`.
2. Set `name`, `prior_weight` (0.0-1.0), and implement `vote(source, trauma) -> EngineResult`.
3. Register it in `lucidcode/validators/orchestra.py` or pass it explicitly via `engines=[...]` when calling `validate_trauma`.
4. Add priors for it to `lucidcode/validators/bayesian.py::DEFAULT_PRIORS`.

## Code style

- Prefer `dataclass` over hand-rolled classes.
- Every public function needs a one-line docstring; multi-paragraph docstrings are discouraged.
- Type hints are required on public API boundaries.
- No comments explaining *what* the code does — only *why*, when non-obvious.

## Reporting a hallucination

If LucidCode shows you a confession you believe is a hallucination, please open an issue with:
- The source snippet (or a minimised repro).
- The confession text.
- The verdict badge and posterior probability.
- Whether the Devil engine was enabled.

We use these to tighten the AST predicates offline.
