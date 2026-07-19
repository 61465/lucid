# Twitter/X launch thread (7 tweets)

**[1/7]**
Your code has been hiding things from you.

We built a tool that makes it confess — in first person — and rigorously refutes every hallucination.

Introducing LucidCode. 🔮

**[2/7]**
Static analysers (Semgrep, Snyk, CodeQL) tell you "rule X matched line 42."
LLM code reviewers hallucinate problems that aren't there.

LucidCode is neither. It's a DX companion that makes code speak — but only after 3 independent engines agree it's telling the truth.

**[3/7]**
Instead of CWE numbers, LucidCode uses psychiatric syndromes:

- Suppression (empty except)
- Amnesia (generic error log)
- Selective_Mutism (bare `except:`)
- Network_Blindspot (no timeout)
- Insomnia (unbounded while True)
- Despair (hedged return)
- …8 more

**[4/7]**
Every confession runs through 3 validators voting in parallel:

- AST re-verifier (deterministic, weight 0.9)
- Sandboxed fuzzer (dynamic, weight 0.7)
- Devil's Advocate LLM (adversarial, weight 0.4)

Bayesian aggregator turns votes into a posterior probability. Hallucinations are logged and dropped.

**[5/7]**
On 22 CVE-inspired Python fixtures:
- Precision = 1.00
- Recall = 1.00
- F1 = 1.00
- 0 false positives on clean-code fixtures
- Median latency 27 ms

Full benchmark reproduces with one command. Numbers small; discipline hopefully large.

**[6/7]**
Free, MIT-licensed. Python 3.10+. One dep (`click`).

CLI: `lucid analyze ./src --sarif out.sarif`
Landing: lucidcode.dev
GitHub: github.com/61465/lucid

Pro tier ($9/mo) adds VS Code inline confessions + team dashboard.

**[7/7]**
Honest limits: Python-only in v4, Devil engine needs an LLM key (else 2-engine mode), fixture set is small.

Would genuinely love to be broken. What confession is LucidCode getting wrong on YOUR code? Reply with a snippet.

/thread
