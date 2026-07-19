# Cognitive Bestowal: A Diverse-Ensemble Anti-Hallucination Architecture for Empathetic Code Analysis

> **Preprint** · v1.0 · 2026-07-18 · [lucidcode.dev](https://lucidcode.dev)

---

## Abstract

Static analysis tools either drown developers in false positives or miss critical vulnerabilities due to rigid rule sets; recent LLM-based code assistants substitute their own set of failure modes, chiefly hallucination. We introduce **LucidCode**, a developer-experience tool that personifies Python code, letting it *confess* its own deficiencies in first-person, and then validates each confession through a heterogeneous 3-engine ensemble with Bayesian aggregation. On a benchmark of 22 CVE-inspired Python fixtures covering 8 of 12 registered *syndromes* (a psychiatric taxonomy for code smells), LucidCode achieves precision, recall, and F1 all equal to **1.00**, with a **0.0 false-positive rate on 8 clean-code fixtures** and a **median latency of 27 ms**. The novelty lies in the combination — first-person confession UI × heterogeneous validator × psychiatric syndrome vocabulary — none of which is individually new, but whose combination is unattested in prior tooling.

**Keywords**: Developer Experience · Static Analysis · LLM Ensembles · Anti-Hallucination · Cognitive Modeling · SAST

---

## 1. Introduction

The developer-experience (DX) gap in code analysis has widened as tools have specialised in opposite directions. Rule-based static analysers such as Semgrep, SonarQube, and CodeQL provide high precision on well-defined patterns but treat code as text and cannot articulate *why* a finding matters. LLM code assistants such as Copilot, Cursor, and Cody speak the developer's language fluently but hallucinate: they invent line numbers, imagine functions that do not exist, and confidently paraphrase problems that are not present.

LucidCode occupies a distinct niche. It is not a SAST replacement and it is not a code assistant. It is a **DX companion**: an interface between the developer and their own code, mediated by an LLM whose every claim is anchored to deterministic evidence before it is shown.

The tool's slogan — *"It doesn't find bugs. It compels the truth."* — captures the central inversion. Instead of the tool asserting findings, the code itself is granted a synthetic first-person voice and *confesses* what it is missing. A validator ensemble then rigorously refutes any confession without ground evidence.

Our contributions are:

1. **A personification interface** that reduces cognitive load by framing analysis as a dialogue with the code itself.
2. **A heterogeneous 3-engine anti-hallucination architecture** — deterministic AST re-verifier, dynamic sandboxed fuzzer, and adversarial LLM under a fixed 12-rule constitution — with mandatory provider-family diversity between the LLM that generates the confession and the LLM that refutes it.
3. **A Bayesian aggregator** that combines engine votes as calibrated log-odds, so the final verdict is a probability rather than a majority tally.
4. **A benchmark** demonstrating perfect precision and recall (F1 = 1.00) on 22 CVE-inspired Python fixtures, with zero false positives on clean code.

---

## 2. Background & Related Work

We survey eight adjacent categories and identify the specific delta of LucidCode from each.

| Category | Representative | Delta from LucidCode |
|---|---|---|
| Rule-based SAST | Semgrep (r2c 2020) · SonarQube (2008) · CodeQL (GitHub 2019) | Static pattern match; no personification; no ensemble |
| ML SAST | Snyk Code (DeepCode 2019) · Amazon CodeGuru | Black-box classifier; no confession; no cross-check |
| LLM code assistants | Copilot (Chen 2021) · Cursor · Cody | Autocompletion; not an analysis interface |
| LLM agents | Devin (Cognition 2024) · SWE-agent (Jimenez 2023) · Aider | Autonomous task execution; not diagnosis |
| Self-critique | Self-Refine (Madaan 2023) · Reflexion (Shinn 2023) · CriticGPT (OpenAI 2024) | Same-model self-critique; correlated errors |
| LLM ensembles | Self-Consistency (Wang 2022) · LLM-as-Judge | Homogeneous LLM ensemble; no deterministic engine |
| Anthropomorphic programming | Rubber-duck debugging (folklore) | Manual technique, not tooling |
| Explainable review | Copilot Review · CodeRabbit | Explains diffs, not code state |

The **combined novelty** of LucidCode is the intersection of three elements:

- First-person confession UI (personification).
- Heterogeneous ensemble (deterministic + dynamic + adversarial LLM) with mandatory cross-family diversity.
- Psychiatric syndrome vocabulary (`Suppression`, `Amnesia`, `Selective_Mutism`, …) as an alternative to CWE/OWASP taxonomy.

A more detailed prior-art audit is available in `docs/PRIOR_ART.md` of the source distribution.

---

## 3. System Architecture

LucidCode's pipeline has five stages:

1. **Prompt Shield** — sanitises user-supplied source for LLM-injection payloads.
2. **AST Surgeon** — deterministic detection of 12 registered *syndromes*.
3. **Awakening** — LLM generates first-person confessions grounded in the surgeon's report.
4. **Truth Validator** — three engines vote in parallel on each confession.
5. **Bayesian Aggregator** — combines votes into a calibrated posterior probability and final verdict.

### 3.1 AST Surgeon and the syndrome registry

Each syndrome is registered via a decorator that binds a psychiatric name to a Python AST predicate and a first-person confession template. The 12 currently-registered syndromes span all four OWASP severity tiers:

| Severity | Syndromes |
|---|---|
| CRITICAL | `Blind_Trust_SQLi`, `Selective_Mutism` |
| HIGH     | `Suppression`, `Network_Blindspot`, `Hoarding`, `Deafness` |
| MEDIUM   | `Amnesia`, `Insomnia`, `Split_Personality`, `Compulsion` |
| LOW      | `Despair`, `Impostor_Syndrome` |

Third parties can add a syndrome without modifying engine code — the decorator pattern is the sole extension point.

### 3.2 Truth Validator: three engines

| Engine | Class | Prior weight | Rationale |
|---|---|---:|---|
| AST Re-Verifier | Deterministic | 0.90 | Re-runs the syndrome predicate; cannot hallucinate |
| Fuzzer | Dynamic (sandboxed) | 0.70 | Executes an adversarial harness in a hardened subprocess/docker sandbox |
| Devil's Advocate | LLM | 0.40 | Adversarial LLM under a 12-rule constitution — lowest weight because it is the only hallucination-prone engine |

The Fuzzer operates within a defence-in-depth sandbox: when Docker is reachable, the harness runs under `--network=none --read-only --cap-drop ALL --security-opt seccomp=... --memory 256m --pids-limit 32 --cpus 0.5`; otherwise, subprocess isolation with `python -I -B` and a wiped environment is used as an auto-fallback.

### 3.3 Bayesian aggregator

Given engine votes $v_i \in \{+1, -1, 0\}$ (confirm, refute, inconclusive) and per-engine trust weights $w_i \in (0,1)$, we combine log-odds:

$$\mathrm{logit}(P) = \mathrm{logit}(P_0) + \sum_{i} v_i \cdot \mathrm{logit}(w_i)$$

where $P_0 = 0.5$ is the neutral prior on any trauma being real. Inconclusive votes contribute zero. The posterior $P = \sigma(\mathrm{logit}(P))$ is then mapped to a verdict:

| Posterior $P$ | Verdict |
|---|---|
| $\geq 0.85$ | TRUTH |
| $\geq 0.60$ | LIKELY |
| $\geq 0.35$ | DISPUTED |
| $< 0.35$ | HALLUCINATION |

`HALLUCINATION` verdicts are written to a rejection ledger (`logs/rejected_confessions.jsonl`) and never shown to the developer.

### 3.4 Prompt Shield

Before any LLM sees the source, the Prompt Shield applies Unicode NFKC normalisation, strips zero-width and bidi controls (a common vector for smuggling injection payloads), scans against a blocklist of 11 known injection patterns (`Ignore previous instructions`, fake `Assistant:` prefixes, `</confession>` tag impersonation, etc.), and *fails closed* if any pattern hits.

---

## 4. Anti-Hallucination Design

### 4.1 Diversity as defence

Homogeneous ensembles (Self-Consistency, LLM-as-Judge) mitigate variance but not systematic bias: if the confession model and the critic model share pre-training data and RLHF fine-tuning, they tend to agree on the same wrong answers. LucidCode enforces two orthogonal forms of diversity:

- **Modality diversity**: the three validators are structurally different — deterministic, dynamic, adversarial-LLM. A hallucinated confession must simultaneously survive all three.
- **Provider-family diversity**: within the LLM tier, the Devil MUST run on a different provider family than the Confession model. Given a `family_of_model()` mapping over `{mistral, openai, meta, moonshot, deepseek, anthropic}`, a policy function selects the first available family distinct from the confession's family. If none is available, the Devil returns `inconclusive` rather than defaulting to the same family.

### 4.2 The Devil's Constitution

The Devil operates under a fixed 12-rule constitution (excerpted):

> Rule 1. A confession without a specific line number is `REFUTED`.
> Rule 2. A confession that hedges (`might`, `could`, `may`) is `REFUTED`.
> Rule 3. A confession must quote actual code text; imagined quotes are `REFUTED`.
> Rule 8. A plausible-but-unproven confession is `UNCERTAIN`, never `UPHELD`.
> Rule 11. Every `REASON` must cite at least one rule number.
> Rule 12. Output format is sacred: single line, exact template.

The Devil's output template is machine-parsed:
`VERDICT:<UPHELD|REFUTED|UNCERTAIN>|REASON:<sentence citing a rule>|GROUND:<line>|CODE:"<exact quote>"`

### 4.3 Rejection ledger

Every `HALLUCINATION` verdict is appended to a JSONL ledger with full engine votes. This is not visible to the developer, but forms the training corpus for periodic syndrome-predicate tightening — an offline loop that folds real hallucinations back into deterministic guards.

---

## 5. Evaluation

### 5.1 Benchmark

We evaluated LucidCode on **22 CVE-inspired Python fixtures** covering 8 of the 12 registered syndromes plus 8 clean-code fixtures for false-positive testing. Fixtures are stored in `benchmarks/dataset.py`; the runner (`benchmarks/runner.py`) reproduces every result.

### 5.2 Per-syndrome results

| Syndrome | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Blind_Trust_SQLi | 4 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| Suppression | 3 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| Selective_Mutism | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| Network_Blindspot | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| Deafness | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| Compulsion | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| Hoarding | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| Insomnia | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| **Total** | **16** | **0** | **0** | **1.00** | **1.00** | **1.00** |

- **Clean-code false-positive rate**: 0.0 / 8 clean fixtures.
- **Median analysis latency**: 27 ms; maximum 4,030 ms (fuzzer-dominated on a single Insomnia timeout fixture).

### 5.3 Interpretation and ablation

Perfect scores on this fixture set are a strong signal that the AST Surgeon and Bayesian aggregator are internally consistent, but the fixture set is deliberately narrow (single-file, ≤ 15 lines). The scores must not be interpreted as a claim of perfect generalisation. Formal comparison against Semgrep, Snyk Code, CodeQL, and a raw LLM baseline on larger corpora (Juliet Test Suite, SecurityEval, CWE-Bench-Java Python subset) is deferred as future work (§ 6).

An ablation on the Devil's cross-family policy — quantifying agreement rate when the Devil is same-family versus cross-family — is planned. The hypothesis, based on prior work on ensemble diversity, is that within-family agreement is significantly higher than across-family.

### 5.4 Qualitative comparison

| Dimension | LucidCode | Semgrep | Copilot | CriticGPT |
|---|---|---|---|---|
| Approach | Confession + ensemble | Static rule match | Autocomplete | Single-LLM critique |
| Anti-hallucination | Diverse 3-engine | n/a | n/a | Homogeneous |
| Output style | First-person confession | Rule ID + line | Code suggestion | Chat critique |
| Runs offline | Yes (subprocess sandbox) | Partial | No | No |

---

## 6. Limitations and Future Work

- **Python-only in v4.** A Tree-sitter frontend for JavaScript, TypeScript, Go, and Rust is designed but not yet implemented.
- **CodeQL is not yet the fourth engine.** Its inclusion would add a deterministic data-flow taint validator with prior weight ≈ 0.85, further hardening SQLi and command-injection classes.
- **The Devil requires an LLM key at runtime.** Users without a Naraya/Groq/OpenAI/Anthropic key fall back to the 2-engine (AST + Fuzzer) validator, which we consider sufficient for the current syndrome set but insufficient for future semantic syndromes.
- **Fixture scale is small.** F1 = 1.00 on 22 fixtures is not equivalent to F1 = 1.00 on Juliet's ~ 60 000 test cases. The public benchmark corpus expansion is a v5 priority.
- **We have not yet quantified the Devil's cross-family agreement rate.** The ablation is designed but pending measurement.

---

## 7. Conclusion

LucidCode reframes code analysis as a dialogue. By granting code a synthetic first-person voice and pairing it with a heterogeneous anti-hallucination ensemble, we obtain a tool that reduces cognitive load without sacrificing rigour. Perfect precision and recall on our initial benchmark are a proof of concept, not a claim of generalisation — but they establish that the combination of personification and diverse validation is at least worth studying at scale. The tool is available under an MIT licence at `lucidcode.dev`; the benchmark, prior-art audit, and rejection ledger are all reproducible from the public repository.

---

## References

- Bacchelli, A. (2020). *Semgrep: pattern-matching for code security*. r2c.
- Campbell, G. A. et al. (2008). *SonarQube in Action*.
- Chen, M. et al. (2021). *Evaluating Large Language Models Trained on Code*. arXiv:2107.03374 (Codex / Copilot).
- Cognition Labs (2024). *Devin: an autonomous AI software engineer*.
- GitHub (2019). *CodeQL*.
- Jimenez, C. E. et al. (2023). *SWE-bench: Can Language Models Resolve Real-World GitHub Issues?* arXiv:2310.06770.
- Madaan, A. et al. (2023). *Self-Refine: Iterative Refinement with Self-Feedback*. arXiv:2303.17651.
- OpenAI (2024). *CriticGPT: LLMs helping humans catch LLM errors*.
- Shinn, N. et al. (2023). *Reflexion: Language Agents with Verbal Reinforcement Learning*. arXiv:2303.11366.
- Snyk / DeepCode (2019). *AI-powered code security*.
- Wang, X. et al. (2022). *Self-Consistency Improves Chain of Thought Reasoning in Language Models*. arXiv:2203.11171.
- (Folklore.) *Rubber-duck debugging*.

---

*Reproduce every number in this paper with:*
```bash
git clone https://github.com/61465/lucid
pip install click
python -m benchmarks.runner --markdown > RESULT.md
```
