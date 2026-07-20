"""Multi-language frontends. Tree-sitter powered."""
from .frontend import detect_language, parse_source, LangResult, LANGUAGES, is_available  # noqa: F401
from .syndromes_multilang import detect_all_multilang  # noqa: F401
