# Product Hunt — LucidCode Listing

## Tagline (60 chars)
> Make your Python code confess its own missing needs.

## Short description (150 chars)
> Novel Python analyser: code speaks in first person, and a 3-engine ensemble rejects every hallucination before you see it. Free, MIT-licensed core.

## Long description (~400 words)

LucidCode is a Python developer-experience tool with an unusual approach.

Instead of showing you "rule X matched at line 42" (like Semgrep), or confidently hallucinating a fix (like most LLM reviewers), LucidCode gives your code a synthetic first-person voice. It confesses what it is missing — and then a rigorous ensemble of validators refuses to show you anything the confession cannot prove.

The confession vocabulary is psychiatric, not bureaucratic. Instead of memorising `CWE-89` or `OWASP A03`, you learn 12 human-readable syndromes: **Suppression** (an empty except handler), **Amnesia** (a generic "something went wrong" log that erases the real cause), **Selective_Mutism** (a bare `except:` that swallows `KeyboardInterrupt`), **Network_Blindspot** (`requests.get()` with no timeout), **Insomnia** (an unbounded `while True`), and 7 more.

Every confession runs through three independent engines simultaneously:

- **AST Re-Verifier** — deterministic, hallucination-immune. Trust weight 0.90.
- **Fuzzer** — synthesises an adversarial harness and runs it in a locked Docker (or subprocess) sandbox. Trust weight 0.70.
- **Devil's Advocate LLM** — an adversarial defence attorney under a 12-rule constitution. It **must** run on a different provider family than the LLM that produced the confession, defeating within-family agreement bias. Trust weight 0.40.

A Bayesian aggregator combines the votes as log-odds and returns a calibrated posterior probability. Confessions that fall below 0.35 posterior are silently logged to a rejection ledger and **never shown**. This is the anti-hallucination guarantee.

### What's inside

- 12 syndromes, decorator-registered (community can add more without touching the engine).
- Docker → subprocess sandbox with `--network=none --read-only --cap-drop ALL` auto-fallback.
- Prompt-injection shield (Unicode normalisation + 11-pattern blocklist + parse gate).
- SARIF 2.1.0 export for GitHub Code Scanning / GitLab SAST.
- CLI with `--json`, `--sarif`, `--min-verdict`, `--stdin` modes.
- 22-fixture CVE-inspired benchmark that reproduces with one command.

### Measured on 22 fixtures

Precision = 1.00, Recall = 1.00, F1 = 1.00, 0 false positives on 8 clean-code fixtures, median latency 27 ms.

Free MIT core. Pro tier ($9/mo) unlocks VS Code inline confessions, team dashboard, and Firecracker microVM sandboxing.

---

## Predicted-question reply drafts

### Q: "How is this different from Semgrep?"
> Semgrep is a rule engine — it fires on patterns you (or the community) authored. LucidCode is a DX companion — it uses an ensemble of engines to make the code itself explain what it's missing, in language you can drop into a Slack thread. They're complementary, not competitive; LucidCode exports SARIF so it can coexist with Semgrep in the same CI.

### Q: "Does my source code get sent to an LLM?"
> Only if you enable the Devil's Advocate engine. The default is a 2-engine validator (AST re-verifier + subprocess fuzzer) that runs 100% locally, no network egress. When you do enable the Devil, we rotate providers by family — you can restrict it to on-prem models via env vars (`LUCID_DEVIL_MODEL_MISTRAL=...`).

### Q: "What about false positives?"
> The benchmark clean-code false-positive rate is 0.0 across 8 clean fixtures. In production usage you should still expect some — the Bayesian aggregator's `DISPUTED` verdict is designed to flag ambiguous cases so you can decide. The rejection ledger records everything the ensemble dropped, so tightening is a matter of PR to the syndrome predicates.
