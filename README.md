# LucidCode

> **It doesn't find bugs. It compels the truth.**

LucidCode is a developer-experience tool that grants your Python code
cognitive self-awareness. Instead of running static rules against your source,
LucidCode makes the code **confess in first person** — and rigorously refutes
any confession that can't be proven.

```
[T1] Suppression @ line 8
  › I confessed: I caught an exception and said nothing.
     Every scream is muffled the moment it starts.
     What am I hiding?
  [VERDICT: TRUTH]  posterior=0.95  driver=ast_reverifier
```

---

## Why LucidCode

| | LucidCode | Semgrep | Copilot | CriticGPT |
|---|---|---|---|---|
| **Approach** | Confession + ensemble | Static rule match | Autocomplete | Self-critique |
| **Anti-hallucination** | Diverse 3-engine | n/a | n/a | Single LLM |
| **Output style** | First-person | Rule ID | Code | Chat |
| **Runs offline** | ✅ subprocess | Partial | ❌ | ❌ |

Full survey of adjacent work in [`docs/PRIOR_ART.md`](docs/PRIOR_ART.md).

---

## Install

```bash
pip install click
git clone https://github.com/lucidcode/lucid
cd lucid
python -m lucidcode.cli syndromes    # list registered syndromes
```

Requires Python 3.10+.
Docker is optional (auto-detected). Without it, LucidCode falls back to
`subprocess -I` sandboxing.

---

## Usage

```bash
# Analyze a file or directory
python -m lucidcode.cli analyze my_project/

# CI gate — exit code 1 if any TRUTH/LIKELY finding
python -m lucidcode.cli analyze my_project/ --min-verdict LIKELY

# JSON output
python -m lucidcode.cli analyze my_project/ --json

# SARIF 2.1.0 for GitHub Code Scanning
python -m lucidcode.cli analyze my_project/ --sarif out.sarif

# Read from stdin
cat suspicious.py | python -m lucidcode.cli analyze --stdin
```

---

## Architecture

```
lucidcode/
├── pipeline.py                ← analyze() top-level entry point
├── core/
│   ├── trauma.py              ← Trauma / EngineVote / ValidatedTrauma / Verdict
│   ├── prompt_shield.py       ← prompt-injection defense
│   └── provenance.py          ← confession sentence provenance tags
├── syndromes/registry.py      ← 12 syndromes (decorator-registered)
├── sandbox/runner.py          ← docker → subprocess fallback
├── validators/
│   ├── ast_reverifier.py      ← weight 0.90 (deterministic, hallucination-immune)
│   ├── fuzzer.py              ← weight 0.70 (runs adversarial code in sandbox)
│   ├── devil.py               ← weight 0.40 (LLM, mandatory provider diversity)
│   ├── bayesian.py            ← calibrated posterior probability
│   └── orchestra.py           ← parallel engine dispatch
├── enrich/network_osint.py    ← threat-intel enrichment via cyberlab.osint
└── cli.py                     ← click-based CLI

benchmarks/
├── dataset.py                 ← 22 CVE-inspired Python fixtures
├── runner.py                  ← scoring: precision / recall / F1 per syndrome
└── RESULT.md                  ← latest scores

tests/regression/              ← 15 unit-level fixtures, pytest-driven
docs/PRIOR_ART.md              ← originality defense
landing/index.html             ← lucidcode.dev
```

---

## The 12 syndromes

| Severity | Name | Detected when |
|---|---|---|
| CRITICAL | `Blind_Trust_SQLi` | SQL built via f-string / concat |
| CRITICAL | `Selective_Mutism` | bare `except:` or `except BaseException` |
| HIGH | `Suppression` | except handler is empty / bare `pass` |
| HIGH | `Network_Blindspot` | `requests.get()` etc. without `timeout=` |
| HIGH | `Hoarding` | `open()`/`socket()` outside `with`, never closed |
| HIGH | `Deafness` | `signal.signal()` with empty handler |
| MEDIUM | `Amnesia` | generic error log ("wrong", "error") |
| MEDIUM | `Insomnia` | `while True` with no `break`/`return` |
| MEDIUM | `Split_Personality` | function returns literals of ≥ 2 distinct types |
| MEDIUM | `Compulsion` | retry loop with no backoff / sleep |
| LOW | `Despair` | hedged string return ("probably", "maybe") |
| LOW | `Impostor_Syndrome` | `assert` with no message |

Adding a new syndrome takes ~30 lines — see the decorator pattern in
`syndromes/registry.py`.

---

## Anti-Hallucination Story

Every confession must survive an ensemble of validators before it's shown:

1. **AST Re-Verifier** — re-runs the syndrome's own AST predicate. Deterministic,
   cannot hallucinate. **Weight: 0.90**.
2. **Fuzzer** — synthesizes an adversarial harness and runs it in a locked
   sandbox (docker `--network none --read-only --cap-drop ALL` when available;
   otherwise `subprocess -I` with wiped env). If the sandbox reports
   `VULN_TRIGGERED` or times out, the trauma is confirmed. **Weight: 0.70**.
3. **Devil's Advocate** (optional) — LLM defense attorney under a 12-rule
   constitution. **Mandatory provider-family diversity**: if the confession
   came from Mistral, the Devil MUST come from a different family (Groq/Kimi/
   Llama/DeepSeek) — this defeats within-family agreement bias.
   **Weight: 0.40** (lowest — LLM votes count least).
4. **Bayesian aggregator** — combines engine votes as log-odds and returns
   a calibrated posterior. Verdicts:
   - `TRUTH` (posterior ≥ 0.85)
   - `LIKELY` (≥ 0.60)
   - `DISPUTED` (≥ 0.35)
   - `HALLUCINATION` (< 0.35) — logged to `logs/rejected_confessions.jsonl`,
     never shown to the user.

---

## Benchmark

Latest run against 22 CVE-inspired fixtures:

```
fixtures=22   precision=1.0   recall=1.0   f1=1.0
clean_fp_rate=0.0             median_latency=27ms
```

Full report: [`benchmarks/RESULT.md`](benchmarks/RESULT.md).
Reproduce with `python -m benchmarks.runner --markdown`.

---

## Regression suite

```bash
pytest tests/regression -q
# 15 passed in 0.04s
```

Auto-generated report: [`tests/regression/REPORT.md`](tests/regression/REPORT.md).

---

## License

MIT — core is free forever. Pro tier (VS Code inline confessions + team
dashboard + Firecracker sandbox) is planned for `$9/mo`.

---

## Status

- **v4 (2026-07-16):** 20/29 planned tasks shipped. Core pipeline, CLI,
  SARIF, benchmark, landing page all working.
- **Pending:** CodeQL data-flow engine · Tree-sitter multi-language ·
  VS Code + GitHub App integrations · Whitepaper · Launch.

Track progress in [`STATUS_v4.md`](STATUS_v4.md).
