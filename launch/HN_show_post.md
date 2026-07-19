# Hacker News — "Show HN" submission

**Title (79 chars):**
> Show HN: LucidCode – Python code that confesses its own missing needs

**URL:** https://lucidcode.dev

---

**Post body:**

Hi HN, I'm sharing LucidCode, a Python static-analysis tool with an unusual UX: instead of listing rule matches, the code itself "confesses" in first person what it's missing, and every confession is cross-checked by a 3-engine anti-hallucination ensemble before it's shown to you.

The reason I built it: I got tired of Semgrep-class output ("rule X matched line 42") that doesn't tell me *why I should care*, and equally tired of LLM code review that confidently invents problems that don't exist. LucidCode is my attempt at the middle path: the LLM writes a first-person confession, but a deterministic AST re-verifier, a sandboxed fuzzer, and an adversarial LLM under a 12-rule "constitution" all vote on whether the confession is real. A Bayesian aggregator turns those votes into a calibrated posterior probability. Anything the ensemble scores below 0.35 is logged and dropped — never shown.

There's a psychiatric flavour to the vocabulary. The 12 syndromes are things like Suppression (empty except handler), Amnesia (generic "something went wrong" log), Selective_Mutism (bare `except:` that swallows KeyboardInterrupt), Network_Blindspot (`requests.get` without timeout), Insomnia (`while True` with no break). It's an alternative taxonomy to CWE/OWASP that I find easier to remember and easier to explain to junior developers.

On a benchmark of 22 CVE-inspired Python fixtures across 8 of the 12 syndromes, LucidCode currently scores precision = 1.00, recall = 1.00, F1 = 1.00, with 0 false positives on 8 clean-code fixtures and a median latency of 27 ms. The full benchmark and dataset are in the repo — I want people to try to break it.

Honest limitations: v4 is Python-only (Tree-sitter frontends for JS/TS/Go/Rust are drafted but not shipped). The Devil's Advocate LLM engine is optional — without any LLM key, LucidCode runs as a 2-engine (AST + Fuzzer) validator, which handles the current syndrome set fine but limits future extensions. The fixture set is deliberately narrow; F1 = 1.00 on 22 files is not a claim of generalisation to production codebases.

MIT-licensed core, Python 3.10+, one dependency (`click`). Pro tier ($9/mo) with VS Code inline confessions and a team dashboard is planned but not required to try it.

Would love feedback on the ensemble design, the syndrome taxonomy, and honest attempts to make it hallucinate.

Repo: https://github.com/61465/lucid
Prior-art audit: https://github.com/61465/lucid/blob/main/docs/PRIOR_ART.md
Benchmark: `python -m benchmarks.runner --markdown`
