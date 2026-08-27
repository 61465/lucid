# ✅ Laundry Executive Summary
*Read time: 30 seconds · Verdict: **APPROVE** (conf 90%)*

## What we found
* Captured **70 business rules** with file+line citations for reviewer sign-off on behavioural equivalence.
* Flagged **5 dead-code candidate(s)** — every one carries ≥ 2 independent evidence lines.

## What worries me most
* **Policy blocker `evidence_before_edit`** — 68 baseline test(s) failed on the UNCHANGED codebase.

## What I ask of you
> Skim the security section (5 mins), then merge through your normal CI. Laundry has no objections.

*Full evidence: 156 artifacts, chain 516f187a3e21dc80…. Session `laundry_9102768c9132`.*