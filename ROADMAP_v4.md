# LucidCode v4 → v5 — Deep Development Roadmap
**Generated:** 2026-07-15  ·  **Author:** NEXUS-AI (Backend Dev) + Claude synthesis
**Project:** `D:\project\doctor` · Slogan: *"It doesn't find bugs. It compels the truth."*

---

## 🎯 Executive Summary

LucidCode v3 is a working prototype (597 LOC, 4 syndromes, 3-engine truth validator,
Naraya-powered LLM confession streamer). v4-v5 evolves it into a **production-ready,
category-defining DX tool** with no direct competitor in the market.

**Novelty claim:** unique combination of
`first-person confession UI` × `deterministic + dynamic + adversarial 3-engine validator`
× `psychiatric syndrome vocabulary`. This trio has no matching prior art.

---

## 🩺 PHASE 1 — Core Hardening & Syndrome Expansion (Week 1-2)

### Goal
Harden the sandbox, expand syndrome coverage from 4 → 12, establish formal benchmark
protocol, and produce a defensible prior-art audit.

### Deliverables

**1.1 Firecracker microVM Sandbox** — `services/sandbox/firecracker_sandbox.py`
Replaces subprocess+timeout. Uses `firecracker-containerd`, seccomp BPF, nftables egress
block (allowlist: OSINT endpoints only), cgroups v2 (CPU=1, mem=512MB), tmpfs + read-only
bind mounts. Fallback path: Docker with equivalent flags for local dev on Windows/macOS.

**1.2 Twelve-Syndrome Registry** — `services/syndromes/syndromes_v4.py`
Pydantic model per syndrome: name, description, AST predicate, confession template, severity.

| # | Syndrome | AST predicate | Severity |
|---|---|---|---|
| 1 | Suppression | empty except handler | HIGH |
| 2 | Blind_Trust_SQLi | f-string SQL literal | CRITICAL |
| 3 | Amnesia | generic error log ("wrong", "error") | MEDIUM |
| 4 | Despair | hedged return ("probably", "maybe") | LOW |
| 5 | **Network_Blindspot** | `requests.*` without `timeout=` | HIGH |
| 6 | **Insomnia** | `while True` without break condition | MEDIUM |
| 7 | **Hoarding** | `open()` / `socket()` without context manager or close | HIGH |
| 8 | **Split_Personality** | function returns >1 distinct type on paths | MEDIUM |
| 9 | **Deafness** | signal handler with empty body | HIGH |
| 10 | **Compulsion** | retry loop without backoff / exponential | MEDIUM |
| 11 | **Impostor_Syndrome** | `assert` without message | LOW |
| 12 | **Selective_Mutism** | swallowed `BaseException` / bare except | CRITICAL |

**1.3 Prior-Art Audit** — `docs/PRIOR_ART.md`
Documented survey with arXiv links proving no direct competitor. Delta-comparison table
vs Semgrep, CodeQL, Snyk Code, Copilot, CriticGPT, Self-Refine, Reflexion.

**1.4 Regression Harness** — `tests/regression/`
30-case fixture with expected verdicts. `pytest --regression` outputs a confusion
matrix per syndrome (precision, recall, F1, hallucination-rejection rate).

### Architectural decisions
- **Firecracker over Docker**: 125ms cold start vs 1-3s, memory footprint 5MB vs 100MB.
  Trade-off: Linux-only for prod (Docker fallback for cross-platform dev).
- **Pydantic syndromes**: hot-reloadable syndrome pack, community can contribute PRs
  without touching engine core.
- **Frontmatter-driven confession templates**: LLM prompt lives with the syndrome,
  not scattered.

---

## 🛡️ PHASE 2 — Anti-Hallucination V2 & Multi-Model Devil (Week 3-4)

### Goal
Fix the correlation risk (Confession + Devil are same LLM), add data-flow verifier,
introduce calibrated confidence, and reject hallucinations more aggressively.

### Deliverables

**2.1 Diversified Devil's Advocate** — `services/validators/devil_advocate_pool.py`
Devil's Advocate now runs on a **different provider family** than the Confession model.
Rotation policy: Confession=Naraya/Mistral → Devil=Groq/Llama-4-Maverick or DeepSeek-R1.
This defeats within-family agreement bias documented in ensemble-LLM literature.

**2.2 Fourth Engine: Data-Flow Taint** — `services/validators/dataflow_engine.py`
Uses **CodeQL CLI** (free for OSS) to verify source→sink for SQLi/XSS/command-injection
syndromes. Deterministic, hallucination-immune. Optional but heavily upweighted for
CRITICAL syndromes.

**2.3 Bayesian Aggregator** — `services/validators/aggregator_bayes.py`
Replaces raw 3/3 majority voting with per-engine calibrated priors (learned from
regression harness). Output: probability distribution over {TRUTH, LIKELY, DISPUTED,
HALLUCINATION} + explicit confidence interval.

**2.4 Prompt Injection Defense** — `services/security/prompt_shield.py`
Sanitizes user-submitted code for embedded prompt-injection attempts
(`SYSTEM:`, `Ignore previous`, tool-call impersonation) before passing to LLM.
Uses a small local classifier + regex + Unicode-normalization.

**2.5 Rejection Ledger** — `logs/rejected_confessions.jsonl`
Every HALLUCINATION verdict is logged with full context. Weekly retraining of
AST predicates from rejection patterns.

### Anti-hallucination techniques from recent research folded in
- **Ensemble diversity** (Guo et al 2024): use models from different families to break
  correlated errors.
- **Chain-of-Verification** (Dhuliawala 2023): confession must generate its own
  verification questions that Devil then answers.
- **Constitutional criticism** (Anthropic 2022): Devil operates on a fixed 12-rule
  constitution rather than free-form.
- **Groundedness scoring** (RAGAS 2024): confession claims are re-anchored to specific
  AST line numbers; unanchored claims are auto-rejected.

---

## 🌐 PHASE 3 — Multi-Language + OSINT-Enriched Network Analysis (Week 5-6)

### Goal
Expand from Python to JS/TS/Go/Rust via Tree-sitter, and add **network-aware
confessions** using our cyberlab OSINT stack.

### Deliverables

**3.1 Tree-Sitter Multi-Language Frontend** — `services/lang/`
`python.py`, `javascript.py`, `typescript.py`, `go.py`, `rust.py`. Each maps
language-specific AST to a common `NormalizedTrauma` schema. Syndrome predicates
become language-parametric.

**3.2 Network-Code Enrichment via OSINT** — `services/enrich/network_osint.py`
When a syndrome touches network code (URLs, IPs, external hosts), Lucid enriches
the confession with real threat intelligence:

| Syndrome + Network context | OSINT enrichment |
|---|---|
| `Network_Blindspot` calling `example.com` | `urlscan(example.com)` → confession includes historical scan verdict |
| Hardcoded IP `1.2.3.4` in code | `greynoise(1.2.3.4)` → "this IP is a known Mirai C2, last seen 3 days ago" |
| Hardcoded API key pattern | `publicwww(<key snippet>)` → count of other public leaks |
| Reference to third-party domain | `leakix(domain)` → is that domain currently leaking? |

**Example enriched confession:**
> *"[T5] I confess (line 42): I call `http://old-api.internal/data` without a timeout.
> I hang forever if it stalls. Worse — GreyNoise reports 3 sightings of this domain
> being scanned by Mirai variants in the past week. My blind trust is not just fragile,
> it may already be compromised."*

**3.3 Confession Provenance** — every confession sentence must trace to either:
`ast_evidence`, `osint_evidence`, or `hedged_speculation`. UI color-codes accordingly.

---

## 🎨 PHASE 4 — Developer Distribution (Week 7-8)

### Goal
Ship LucidCode where developers actually live: CLI, VS Code extension, GitHub App.

### Deliverables

**4.1 CLI** — `cli/lucid`
```
lucid analyze ./src              # scan directory
lucid analyze file.py --json     # machine output
lucid analyze --sarif > out.sarif # CI-compatible
lucid awaken --interactive       # REPL mode
```

**4.2 VS Code Extension** — `extensions/vscode/`
LSP-based. Inline gold-underline on traumatized lines. Hover shows the confession +
verdict badge. Ctrl+. reveals full 3-engine vote transcript.

**4.3 GitHub App** — `extensions/github-app/`
On PR, posts a single collapsed comment titled *"The code has confessed 3 truths."*
Expandable: each confession + verdict + `Fix suggested by defense attorney` block.

**4.4 SARIF exporter** — `services/exporters/sarif.py`
Compatible with GitHub Code Scanning + GitLab SAST + Bitbucket Code Insights.

**4.5 Landing page** — `landing/lucidcode.dev`
Copy angle: *"Your code has been hiding things from you. Let it speak."*
Above the fold: live 15-second demo — paste code → hear it confess → see 3 engines vote.
Below: 3-column comparison vs Semgrep / Copilot / CriticGPT.

---

## 📈 PHASE 5 — Formal Evaluation + Paper + Launch (Week 9-10)

### Goal
Prove LucidCode's edge scientifically, publish, launch.

### Deliverables

**5.1 Benchmark Suite** — `benchmarks/`
LucidCode vs Semgrep vs Snyk Code vs CodeQL vs raw GPT-4o on:
- **CWE-Bench-Java** (subset ported to Python)
- **Juliet Test Suite** (Python + JS)
- **SecurityEval** (Siddiq & Santos 2022)
- **50 curated real CVEs** from OSS 2024-2026
Metrics: precision, recall, F1, hallucination-rate, per-syndrome latency.

**5.2 Whitepaper** — `paper/lucidcode.pdf`
Title: *"Cognitive Bestowal: A Diverse-Ensemble Anti-Hallucination Architecture for
Empathetic Code Analysis."* Target: arXiv cs.SE + Anthropic-style DX blog cross-post.

**5.3 Launch Package**
- Product Hunt (Tuesday drop)
- Hacker News: *"Show HN: I made code confess its bugs in first person"*
- Anthropic Discord + OpenAI DX community
- 60-second demo video
- Free tier (OSS core, MIT) + Pro tier ($9/mo VS Code advanced features + team dashboard)

---

## 🔥 Kill-Scenarios & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Naraya free tier throttles → confession stalls | High | Fallback to Groq (already wired in company runner); local Ollama option for full offline mode |
| Devil's Advocate consistently agrees with Confession (correlation) | Critical | Diversified provider pool (Phase 2.1); measure agreement rate every release |
| LLM hallucinates a "confession" for code that has no trauma | Critical | AST Surgeon is deterministic gate: no trauma → no confession possible |
| Sandbox escape via Firecracker vulnerability | Existential | Multiple layers (seccomp + nftables + cgroups) + no persistent storage + submit sandboxed code to `urlscan_submit` for meta-analysis |
| Developer says *"this is gimmicky, I want real SAST"* | Medium | Positioning as **DX companion**, not SAST replacement; SARIF export lets it coexist with Semgrep/Snyk in same CI |
| Anthropic / OpenAI ships similar first-party feature | High | Move fast; establish syndromes-as-open-standard so switching cost stays low; brand ownership |
| Legal / trademark: "Lucid" is common | Medium | Register `LucidCode` (compound), secure domain `lucidcode.dev` + `.io`; keep philosophical framing as brand moat |
| Cost blowout: heavy LLM usage per analysis | Medium | Aggressive caching by AST hash; free tier limits to 100 confessions/day per user |

---

## 📚 References (external building blocks)

- **Firecracker** (AWS) — microVM sandboxing
- **Tree-sitter** (GitHub) — multi-language AST
- **CodeQL CLI** (GitHub) — free-for-OSS data-flow analysis
- **Semgrep** (Semgrep Inc) — 5000+ open rules to translate into syndromes
- **Naraya router** (Bynara) — 7M tokens/day free (current primary)
- **Groq API** — kimi-k2 + llama-4-maverick + DeepSeek-R1 (2026-Q3 lineup)

---

## ✅ Definition of Done for v5

1. 12 syndromes across 5 languages, all with green regression tests.
2. 4-engine validator with Bayesian aggregation + confidence intervals.
3. Firecracker sandbox in prod, seccomp + egress-block verified.
4. CLI + VS Code + GitHub App shipped, at least 10 real dogfooders.
5. Benchmark paper published showing better hallucination-rejection than any single-LLM
   baseline.
6. Landing page live at lucidcode.dev; Product Hunt + HN launched.
7. 500+ GitHub stars, 3+ community-contributed syndromes.
