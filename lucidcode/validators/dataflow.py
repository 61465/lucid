"""
Data-Flow Taint Engine — the 4th validator, powered by CodeQL CLI.

For CRITICAL syndromes with source→sink semantics (SQLi, XSS, command
injection) a deterministic taint analysis is the gold-standard corroborator.

This engine wraps `codeql` (from the GitHub CodeQL CLI) as an external tool:
    * If the binary is not on PATH, the engine returns `inconclusive` and
      the ensemble degrades gracefully to the 3-engine mode.
    * If present, a per-language QL query is compiled and run against a
      temporary CodeQL database built from the source snippet.

Setup instructions for a real integration:
    # https://github.com/github/codeql-cli-binaries/releases
    pip install codeql  # unofficial helper, or download the binary
    codeql pack download codeql/python-queries

For the LucidCode benchmark we treat this engine as OPTIONAL — its prior
weight (0.85) is the highest of the LLM-optional engines, but its absence
does not break scoring on the current 22-fixture corpus.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from lucidcode.core.trauma import Trauma
from .base import Engine, EngineResult


# Syndromes for which CodeQL adds real signal beyond AST/Fuzzer.
_TAINT_SYNDROMES = {
    "Blind_Trust_SQLi",       # source→sink from user input to sql.execute
    "Network_Blindspot",      # url derived from user input
    # (future) OS_Command_Injection, XSS, Path_Traversal — not yet syndromes
}


def _codeql_binary() -> Optional[str]:
    """Path to codeql, or None if missing."""
    return shutil.which("codeql")


class DataflowEngine(Engine):
    name = "dataflow"
    prior_weight = 0.85    # 2nd-highest — deterministic + semantic

    def __init__(self,
                 codeql_path: str | None = None,
                 query_dir: str | None = None,
                 timeout: int = 60) -> None:
        self.codeql = codeql_path or _codeql_binary()
        self.query_dir = query_dir
        self.timeout = timeout

    def vote(self, source: str, trauma: Trauma) -> EngineResult:
        if trauma.syndrome not in _TAINT_SYNDROMES:
            return EngineResult(
                vote="inconclusive",
                reason=f"{trauma.syndrome} not in taint-analysis scope",
            )
        if not self.codeql:
            return EngineResult(
                vote="inconclusive",
                reason="codeql binary not installed — engine offline",
                meta={"install_hint": "https://github.com/github/codeql-cli-binaries"},
            )
        return self._run_codeql(source, trauma)

    def _run_codeql(self, source: str, trauma: Trauma) -> EngineResult:
        with tempfile.TemporaryDirectory(prefix="lucid_ql_") as tdir:
            src_dir = Path(tdir) / "src"
            src_dir.mkdir()
            ext = ".py" if trauma.lang == "python" else ".js"
            (src_dir / f"module{ext}").write_text(source, encoding="utf-8")

            db_dir = Path(tdir) / "db"
            create = subprocess.run(
                [self.codeql, "database", "create", str(db_dir),
                 "--language=" + trauma.lang,
                 "--source-root=" + str(src_dir),
                 "--quiet"],
                capture_output=True, text=True, timeout=self.timeout,
            )
            if create.returncode != 0:
                return EngineResult(
                    vote="inconclusive",
                    reason=f"codeql db create failed: {create.stderr[:200]}",
                )

            query = self._pick_query(trauma.syndrome, trauma.lang)
            if not query:
                return EngineResult(
                    vote="inconclusive",
                    reason=f"no bundled query for {trauma.syndrome}",
                )

            analyze = subprocess.run(
                [self.codeql, "database", "analyze", str(db_dir),
                 query, "--format=sarif-latest",
                 "--output=" + str(Path(tdir) / "out.sarif"),
                 "--quiet"],
                capture_output=True, text=True, timeout=self.timeout,
            )
            if analyze.returncode != 0:
                return EngineResult(
                    vote="inconclusive",
                    reason=f"codeql analyze failed: {analyze.stderr[:200]}",
                )

            sarif_path = Path(tdir) / "out.sarif"
            if not sarif_path.exists():
                return EngineResult(vote="inconclusive", reason="no SARIF produced")

            import json
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            results = sarif.get("runs", [{}])[0].get("results", [])
            hits_at_line = [
                r for r in results
                for loc in r.get("locations", [])
                if loc.get("physicalLocation", {}).get("region", {}).get("startLine") == trauma.line
            ]
            if hits_at_line:
                return EngineResult(
                    vote="confirm",
                    reason=f"CodeQL confirmed taint at line {trauma.line} ({len(hits_at_line)} result)",
                    meta={"rule_id": hits_at_line[0].get("ruleId", "")},
                )
            return EngineResult(
                vote="refute",
                reason=f"CodeQL query returned no taint at line {trauma.line}",
            )

    def _pick_query(self, syndrome: str, lang: str) -> Optional[str]:
        """Return path to a pre-installed CodeQL query for this syndrome."""
        if not self.query_dir:
            # convention: bundled queries live in codeql-queries/<lang>/<syndrome>.ql
            bundled = Path(__file__).resolve().parent.parent.parent / "codeql-queries" / lang / f"{syndrome}.ql"
            return str(bundled) if bundled.exists() else None
        p = Path(self.query_dir) / lang / f"{syndrome}.ql"
        return str(p) if p.exists() else None


if __name__ == "__main__":
    from lucidcode.core.trauma import Trauma
    e = DataflowEngine()
    fake = Trauma(id="T1", syndrome="Blind_Trust_SQLi", severity="CRITICAL",
                  line=2, evidence="", confession="", predicate={})
    r = e.vote("q = f\"SELECT * FROM t WHERE n = '{x}'\"", fake)
    print(f"vote={r.vote}  reason={r.reason}")
    print(f"codeql available: {_codeql_binary() is not None}")
