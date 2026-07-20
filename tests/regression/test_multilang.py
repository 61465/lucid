"""Tree-sitter multi-language detection tests."""
import pytest

try:
    from lucidcode.lang import detect_all_multilang, is_available
except ImportError:
    is_available = lambda: False
    detect_all_multilang = None

pytestmark = pytest.mark.skipif(not is_available(), reason="tree-sitter not installed")


def _syndromes(hits):
    return {h["syndrome"] for h in hits}


def test_js_empty_catch_and_fetch_no_timeout():
    src = (
        "async function f(){\n"
        "  try {\n"
        "    const r = await fetch('http://x.com');\n"
        "  } catch (e) {}\n"
        "}\n"
    )
    hits = detect_all_multilang(src, "javascript")
    got = _syndromes(hits)
    assert "Network_Blindspot" in got
    assert "Suppression" in got


def test_ts_infinite_while():
    src = (
        "function spin() {\n"
        "  while (true) {\n"
        "    const x = 1;\n"
        "  }\n"
        "}\n"
    )
    hits = detect_all_multilang(src, "typescript")
    assert "Insomnia" in _syndromes(hits)


def test_ts_assert_without_message():
    src = "assert(x === 1);\n"
    hits = detect_all_multilang(src, "typescript")
    assert "Impostor_Syndrome" in _syndromes(hits)


def test_go_bare_for_loop():
    src = (
        "package main\n"
        "func spin() {\n"
        "    for {\n"
        "        x := 1\n"
        "    }\n"
        "}\n"
    )
    hits = detect_all_multilang(src, "go")
    assert "Insomnia" in _syndromes(hits)


def test_go_error_dropped_via_blank():
    src = (
        "package main\n"
        "func run() {\n"
        "    _, err := doThing()\n"
        "    _ = err\n"
        "}\n"
    )
    hits = detect_all_multilang(src, "go")
    assert "Selective_Mutism" in _syndromes(hits)


def test_python_falls_back_to_native_ast():
    src = "def f():\n    try: pass\n    except: pass\n"
    hits = detect_all_multilang(src, "python")
    assert "Suppression" in _syndromes(hits)
