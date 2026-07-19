# Community launch posts

## Anthropic Discord (`#dev-tools` or `#projects`)

**Title:** Feedback wanted — provider-rotation policy for anti-hallucination validators

Hi folks. I've been building **LucidCode** — a Python DX tool where code confesses its missing needs in first person, then goes through a 3-engine anti-hallucination ensemble before anything is shown. The ensemble is deliberately heterogeneous: a deterministic AST re-verifier, a sandboxed fuzzer, and an adversarial LLM ("Devil's Advocate") under a 12-rule constitution.

The design decision I'd love your critique on: **the Devil is forced to run on a different provider family than the Confession model.** I've mapped `mistral`, `openai`, `meta`, `moonshot`, `deepseek`, `anthropic` as separate families; if the Confession came from a Mistral-family model, the Devil MUST come from another. The idea is to defeat within-family agreement bias, but I haven't quantified the effect yet — the ablation is designed but pending.

If anyone here has published or informally measured intra-family agreement in critique tasks, or if you think the mapping is wrong, I'd love to hear it. Repo + full paper: https://lucidcode.dev.

MIT, F1 = 1.00 on 22 CVE fixtures, honest about the fixture set being narrow. Not selling anything.

---

## OpenAI DX community (or /r/OpenAI · discord `#builds`)

**Title:** Comparing an anti-hallucination code-review ensemble against CriticGPT-style single-model critique

Sharing **LucidCode** (Python DX tool) for anyone who's thought hard about single-model critique. The core question I'm interested in: when the same model both generates AND critiques, how much of the agreement is signal vs shared training bias?

LucidCode's answer is a heterogeneous ensemble — deterministic AST re-verifier + sandboxed fuzzer + LLM Devil forced to a different provider family than the Confession model. The LLM's vote is intentionally weighted at 0.40 in the Bayesian aggregator; the deterministic engine at 0.90. So a hallucinated confession has to survive an AST re-check and a subprocess sandbox before the LLM even gets a chance to argue.

Would love a compare-and-contrast with CriticGPT-style patterns from anyone here who's implemented one. Especially interested in whether same-family critics produced calibrated confidence in your setups, or whether you needed a mixture of methods to get useful signal.

Benchmark, paper, code all at https://lucidcode.dev — MIT, free. Sharing for feedback, not launch.
