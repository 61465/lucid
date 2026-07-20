/**
 * LucidCode GitHub App — Probot handler for pull_request events.
 *
 * Flow:
 *   1. On pull_request.opened / synchronize / reopened:
 *      a. Clone the PR head into a temp dir (shallow, single-branch).
 *      b. Spawn `python -m lucidcode.cli analyze <dir> --json --min-verdict LIKELY`.
 *      c. Group findings per file, format a single collapsible PR review comment.
 *      d. If any TRUTH findings exist → request-changes review; else comment-only.
 *
 * Requires:
 *   - Node 20+
 *   - Python 3.10+ with `pip install lucidcode` on PATH (or LUCID_PYTHON env)
 *   - Repo permissions: `contents: read`, `pull-requests: write`, `checks: write`
 *   - Env vars: APP_ID, PRIVATE_KEY, WEBHOOK_SECRET (Probot defaults)
 *
 * Configure via `.github/lucidcode.yml` at the repo root:
 *   min_verdict: LIKELY          # TRUTH | LIKELY | DISPUTED
 *   request_changes_on: TRUTH    # TRUTH | LIKELY | never
 *   fail_check_on: TRUTH         # gate the "LucidCode" check-run
 */
const { spawn } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs/promises");
const tmp = require("tmp-promise");
const simpleGit = require("simple-git");

const PYTHON = process.env.LUCID_PYTHON || "python";
const DEFAULT_CONFIG = {
  min_verdict: "LIKELY",
  request_changes_on: "TRUTH",
  fail_check_on: "TRUTH",
};

module.exports = (app) => {
  app.on(
    ["pull_request.opened", "pull_request.synchronize", "pull_request.reopened"],
    async (context) => {
      const pr = context.payload.pull_request;
      const { owner, repo } = context.repo();

      // Read per-repo config
      let cfg = { ...DEFAULT_CONFIG };
      try {
        const raw = await context.config("lucidcode.yml", DEFAULT_CONFIG);
        cfg = { ...DEFAULT_CONFIG, ...(raw || {}) };
      } catch (_) {}

      // Open a check-run "in-progress" so the developer sees it live
      const check = await context.octokit.checks.create(
        context.repo({
          name: "LucidCode",
          head_sha: pr.head.sha,
          status: "in_progress",
          started_at: new Date().toISOString(),
        }),
      );

      // Clone + analyze in a temp dir
      const dir = await tmp.dir({ unsafeCleanup: true });
      let findings = [];
      try {
        const cloneUrl = pr.head.repo.clone_url;
        const git = simpleGit(dir.path);
        await git.clone(cloneUrl, dir.path, ["--depth", "1", "--branch", pr.head.ref]);

        const result = await runLucid(dir.path, cfg.min_verdict);
        findings = result.findings;
      } catch (e) {
        context.log.error(e, "LucidCode analysis failed");
        await context.octokit.checks.update(context.repo({
          check_run_id: check.data.id,
          status: "completed",
          conclusion: "neutral",
          completed_at: new Date().toISOString(),
          output: { title: "LucidCode", summary: `Analysis errored: ${e.message.slice(0, 400)}` },
        }));
        return;
      } finally {
        await dir.cleanup();
      }

      // Compose PR review
      const body = renderReviewBody(findings);
      const hasTruth = findings.some(f => f.verdict === "TRUTH");
      const eventForReview =
        cfg.request_changes_on === "never" ? "COMMENT" :
        cfg.request_changes_on === "TRUTH" && hasTruth ? "REQUEST_CHANGES" :
        cfg.request_changes_on === "LIKELY" && findings.length > 0 ? "REQUEST_CHANGES" :
        "COMMENT";

      if (findings.length > 0) {
        await context.octokit.pulls.createReview(context.repo({
          pull_number: pr.number,
          commit_id: pr.head.sha,
          event: eventForReview,
          body,
        }));
      }

      // Close the check-run
      const failCheck = cfg.fail_check_on === "TRUTH" && hasTruth
        || cfg.fail_check_on === "LIKELY" && findings.length > 0;
      await context.octokit.checks.update(context.repo({
        check_run_id: check.data.id,
        status: "completed",
        conclusion: failCheck ? "failure" : (findings.length ? "neutral" : "success"),
        completed_at: new Date().toISOString(),
        output: {
          title: `LucidCode — ${findings.length} confession${findings.length === 1 ? "" : "s"}`,
          summary: findings.length
            ? `The code has confessed ${findings.length} truth${findings.length === 1 ? "" : "s"}. See PR review for details.`
            : "The code confessed nothing. Clean at the configured threshold.",
        },
      }));
    },
  );
};

// ─── LucidCode CLI invocation ─────────────────────────────────
function runLucid(cwd, minVerdict) {
  return new Promise((resolve, reject) => {
    const args = ["-m", "lucidcode.cli", "analyze", ".",
                  "--json", "--min-verdict", minVerdict, "--no-color"];
    const child = spawn(PYTHON, args, { cwd, shell: false });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", d => stdout += d.toString("utf-8"));
    child.stderr.on("data", d => stderr += d.toString("utf-8"));
    child.on("error", reject);
    child.on("close", code => {
      if (code === null || code > 1) {
        return reject(new Error(`lucid exited ${code}: ${stderr.slice(0, 300)}`));
      }
      let files;
      try { files = JSON.parse(stdout); } catch (e) {
        return reject(new Error(`lucid JSON parse failed: ${stdout.slice(0, 200)}`));
      }
      const flat = [];
      for (const f of files) {
        for (const finding of (f.findings || [])) {
          flat.push({
            path: f.path,
            verdict: finding.verdict,
            posterior: finding.posterior_probability,
            trauma: finding.trauma,
            dominant: finding.dominant_evidence,
          });
        }
      }
      resolve({ findings: flat });
    });
  });
}

// ─── PR comment renderer ──────────────────────────────────────
function renderReviewBody(findings) {
  if (findings.length === 0) {
    return "> The code has confessed **nothing**. Nothing at the configured threshold.\n\n_Powered by [LucidCode](https://lucidcode.dev)_";
  }

  const emoji = { TRUTH: "🔴", LIKELY: "🟡", DISPUTED: "🔵" };
  const lines = [
    `> The code has confessed **${findings.length} truth${findings.length === 1 ? "" : "s"}**.`,
    "",
    "<details><summary>Show confessions</summary>",
    "",
  ];
  const byFile = {};
  for (const f of findings) (byFile[f.path] ||= []).push(f);
  for (const [file, group] of Object.entries(byFile)) {
    lines.push(`#### \`${file}\``);
    lines.push("");
    for (const f of group) {
      const t = f.trauma;
      const label = `${emoji[f.verdict] || "⚪"} **${f.verdict}** · ${t.syndrome} · line ${t.line} · posterior ${f.posterior.toFixed(2)}`;
      lines.push(`- ${label}`);
      lines.push(`  > ${(t.confession || t.evidence || "").replace(/\n/g, " ").slice(0, 500)}`);
    }
    lines.push("");
  }
  lines.push("</details>");
  lines.push("");
  lines.push("_Every confession above passed a 3-engine anti-hallucination validator. Rejected confessions never reach this comment._");
  lines.push("");
  lines.push("_Powered by [LucidCode](https://lucidcode.dev) · [Configure via `.github/lucidcode.yml`](https://github.com/61465/lucid/tree/main/extensions/github-app)_");
  return lines.join("\n");
}
