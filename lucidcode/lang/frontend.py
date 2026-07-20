"""
Tree-sitter multi-language frontend.

Supported languages (in v4):
    python      .py
    javascript  .js / .jsx / .mjs / .cjs
    typescript  .ts / .tsx
    go          .go

Public API:
    detect_language(path_or_source) -> "python" | "javascript" | "typescript" | "go" | None
    parse_source(source, lang) -> LangResult(tree, lang, parser)
    LANGUAGES = {"python": Language, ...}

Tree-sitter parsing is universal; syndrome detection per language lives in
`syndromes_multilang.py` which maps language-specific node types to the
same 12-syndrome vocabulary as the Python AST Surgeon.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    from tree_sitter import Language, Parser
    import tree_sitter_python
    import tree_sitter_javascript
    import tree_sitter_typescript
    import tree_sitter_go
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False
    Language = Parser = None  # type: ignore


LANGUAGES: dict[str, Any] = {}
_PARSERS: dict[str, Any] = {}

if _AVAILABLE:
    LANGUAGES = {
        "python":     Language(tree_sitter_python.language()),
        "javascript": Language(tree_sitter_javascript.language()),
        "typescript": Language(tree_sitter_typescript.language_typescript()),
        "go":         Language(tree_sitter_go.language()),
    }
    for name, lang in LANGUAGES.items():
        _PARSERS[name] = Parser(lang)


_EXTENSION_MAP = {
    ".py":  "python",  ".pyi": "python",
    ".js":  "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript",
    ".ts":  "typescript", ".tsx": "typescript",
    ".go":  "go",
}


@dataclass
class LangResult:
    """Result of parsing source in a given language."""
    tree: Any                    # tree_sitter.Tree
    language: str
    parser: Any                  # tree_sitter.Parser
    source_bytes: bytes


def detect_language(path_or_source: str | Path,
                    is_source: bool = False) -> Optional[str]:
    """Detect language from file extension. Returns None if unsupported."""
    if is_source:
        # crude source-only heuristic (used when analyzing stdin)
        text = str(path_or_source)[:2000]
        if "package " in text and "func " in text:
            return "go"
        if ("import " in text or "def " in text) and ":" in text:
            return "python"
        if "interface " in text or ": string" in text or ": number" in text:
            return "typescript"
        if "function " in text or "const " in text or "let " in text or "=>":
            return "javascript"
        return None
    p = Path(path_or_source)
    return _EXTENSION_MAP.get(p.suffix.lower())


def parse_source(source: str, language: str) -> Optional[LangResult]:
    """Parse `source` in `language`. Returns None if language unsupported."""
    if not _AVAILABLE:
        return None
    parser = _PARSERS.get(language)
    if not parser:
        return None
    source_bytes = source.encode("utf-8", errors="replace")
    tree = parser.parse(source_bytes)
    return LangResult(
        tree=tree, language=language, parser=parser, source_bytes=source_bytes,
    )


def is_available() -> bool:
    """True if tree-sitter and all grammar packages are installed."""
    return _AVAILABLE


if __name__ == "__main__":
    print(f"tree-sitter available: {is_available()}")
    if is_available():
        print(f"languages: {sorted(LANGUAGES)}")
    for src, lang in [
        ('def f(): return 1',                 'python'),
        ('function f(){return 1}',            'javascript'),
        ('const x: number = 1;',              'typescript'),
        ('package main\nfunc main(){}',       'go'),
    ]:
        r = parse_source(src, lang)
        if r:
            print(f"  {lang:12s} root={r.tree.root_node.type} nodes~{r.tree.root_node.child_count}")
