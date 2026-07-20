/**
 * LucidCode VS Code extension — thin wrapper around `python -m lucidcode.cli`.
 *
 * On save (or command), spawn the CLI with `--json`, parse the finding list,
 * and turn each finding into a Diagnostic surfaced in the Problems panel.
 *
 * Kept intentionally small: no LSP daemon, no bundled Python. Users must have
 * `pip install lucidcode` in the interpreter given by `lucidcode.pythonPath`.
 */
import * as vscode from "vscode";
import { spawn } from "child_process";
import * as path from "path";

const COLLECTION = "lucidcode";
const VERDICT_TO_SEVERITY: Record<string, vscode.DiagnosticSeverity> = {
  TRUTH:    vscode.DiagnosticSeverity.Error,
  LIKELY:   vscode.DiagnosticSeverity.Warning,
  DISPUTED: vscode.DiagnosticSeverity.Information,
};

const VERDICT_RANK: Record<string, number> = {
  DISPUTED: 0, LIKELY: 1, TRUTH: 2,
};

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let latestReport: any = null;

export function activate(context: vscode.ExtensionContext) {
  diagnostics = vscode.languages.createDiagnosticCollection(COLLECTION);
  context.subscriptions.push(diagnostics);
  output = vscode.window.createOutputChannel("LucidCode");
  context.subscriptions.push(output);

  context.subscriptions.push(
    vscode.commands.registerCommand("lucidcode.analyzeCurrentFile", () =>
      analyzeActiveEditor()),
    vscode.commands.registerCommand("lucidcode.analyzeWorkspace", () =>
      analyzeWorkspace()),
    vscode.commands.registerCommand("lucidcode.showLatestReport", () =>
      showLatestReport()),
  );

  // Run-on-save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      const cfg = vscode.workspace.getConfiguration("lucidcode");
      if (!cfg.get<boolean>("runOnSave", true)) return;
      if (!isSupported(doc.languageId)) return;
      void analyzeFile(doc.uri);
    }),
  );

  // Clear diagnostics when a file is closed
  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument(doc => {
      diagnostics.delete(doc.uri);
    }),
  );
}

export function deactivate() {
  diagnostics?.dispose();
  output?.dispose();
}

function isSupported(langId: string): boolean {
  return ["python", "javascript", "typescript", "typescriptreact",
          "javascriptreact", "go"].includes(langId);
}

async function analyzeActiveEditor() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("LucidCode: no active editor");
    return;
  }
  await analyzeFile(editor.document.uri);
}

async function analyzeWorkspace() {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage("LucidCode: no workspace folder open");
    return;
  }
  await analyzePath(folders[0].uri.fsPath);
}

async function analyzeFile(uri: vscode.Uri) {
  await analyzePath(uri.fsPath, uri);
}

async function analyzePath(fsPath: string, singleFileUri?: vscode.Uri) {
  const cfg = vscode.workspace.getConfiguration("lucidcode");
  const pythonPath = cfg.get<string>("pythonPath", "python");
  const minVerdict = cfg.get<string>("minVerdict", "LIKELY");

  const args = ["-m", "lucidcode.cli", "analyze", fsPath,
                "--json", "--min-verdict", minVerdict, "--no-color"];

  output.appendLine(`[lucid] ${pythonPath} ${args.join(" ")}`);
  const jsonOut = await runProcess(pythonPath, args);
  if (!jsonOut) return;

  let report: any[];
  try {
    report = JSON.parse(jsonOut);
  } catch (e) {
    output.appendLine(`[lucid] JSON parse failed: ${e}`);
    return;
  }
  latestReport = report;

  // Clear per-file diagnostics before repopulating
  if (singleFileUri) {
    diagnostics.delete(singleFileUri);
  } else {
    diagnostics.clear();
  }

  let totalFindings = 0;
  for (const file of report) {
    const uri = vscode.Uri.file(path.resolve(file.path));
    const diags: vscode.Diagnostic[] = [];
    for (const finding of file.findings || []) {
      const trauma = finding.trauma;
      const line = Math.max(0, (trauma.line ?? 1) - 1);
      const range = new vscode.Range(line, 0, line, 200);
      const severity = VERDICT_TO_SEVERITY[finding.verdict]
        ?? vscode.DiagnosticSeverity.Information;
      const msg = `[${finding.verdict} ${finding.posterior_probability.toFixed(2)}] `
        + `${trauma.syndrome}: ${(trauma.confession || trauma.evidence || "").slice(0, 300)}`;
      const d = new vscode.Diagnostic(range, msg, severity);
      d.source = "LucidCode";
      d.code = trauma.syndrome;
      diags.push(d);
    }
    if (diags.length > 0) {
      diagnostics.set(uri, diags);
      totalFindings += diags.length;
    }
  }
  vscode.window.setStatusBarMessage(
    `$(zap) LucidCode: ${totalFindings} finding${totalFindings === 1 ? "" : "s"}`, 5000);
}

function showLatestReport() {
  if (!latestReport) {
    vscode.window.showInformationMessage("LucidCode: no report yet, run analyze first");
    return;
  }
  const doc = vscode.workspace.openTextDocument({
    content: JSON.stringify(latestReport, null, 2),
    language: "json",
  });
  doc.then(d => vscode.window.showTextDocument(d, { preview: true }));
}

function runProcess(cmd: string, args: string[]): Promise<string | null> {
  return new Promise(resolve => {
    const child = spawn(cmd, args, { shell: false });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString("utf-8")));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString("utf-8")));
    child.on("error", err => {
      output.appendLine(`[lucid] spawn failed: ${err.message}`);
      vscode.window.showErrorMessage(
        `LucidCode: cannot run '${cmd}' — install with 'pip install lucidcode' and set lucidcode.pythonPath in settings.`);
      resolve(null);
    });
    child.on("close", code => {
      // exit code 1 is expected when findings are present; 0 = clean; other = error
      if (code === null || code > 1) {
        output.appendLine(`[lucid] exit ${code}, stderr: ${stderr.slice(0, 400)}`);
        resolve(null);
        return;
      }
      resolve(stdout);
    });
  });
}
