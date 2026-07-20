# LucidCode for VS Code

Surfaces LucidCode findings as inline diagnostics in the Problems panel.

## Install (dev)

```bash
cd extensions/vscode
npm install
npm run compile
# then open the folder in VS Code and press F5 to launch a debug window
```

## Requires

- Python 3.10+ with `lucidcode` installed (`pip install -e ../..`)
- Set `lucidcode.pythonPath` in VS Code settings if `python` isn't on PATH

## Commands

- `LucidCode: Analyze current file`
- `LucidCode: Analyze entire workspace`
- `LucidCode: Show latest report`

## Settings

- `lucidcode.pythonPath` — default `"python"`
- `lucidcode.minVerdict` — `TRUTH` / `LIKELY` (default) / `DISPUTED`
- `lucidcode.runOnSave` — default `true`

## How it works

The extension is intentionally thin. It spawns `python -m lucidcode.cli analyze
<path> --json --min-verdict <v> --no-color` and turns each finding into a
`vscode.Diagnostic`:

- `TRUTH` → Error (red squiggle)
- `LIKELY` → Warning (yellow squiggle)
- `DISPUTED` → Information (blue squiggle)

Rejected `HALLUCINATION` verdicts never reach the extension — LucidCode's CLI
filters them out server-side.

## Publishing (not yet)

To publish to the VS Code Marketplace:
```bash
npm install -g @vscode/vsce
vsce package     # produces .vsix
vsce publish     # requires PAT + verified publisher
```
