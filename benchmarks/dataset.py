"""
CVE-inspired Python fixtures for LucidCode benchmark.

Each entry has:
    name              : short slug
    cve               : CVE ID (real or _INVENTED_ for training purposes)
    source            : Python source (must ast.parse cleanly)
    expected_findings : list of {syndrome, line, min_verdict} — empty for clean code
    notes             : optional string

Coverage target across 12 syndromes:
    Blind_Trust_SQLi   × 5   Network_Blindspot × 3   Selective_Mutism × 2
    Hoarding           × 2   Deafness         × 2    Insomnia         × 2
    Suppression        × 1   Compulsion       × 1
    clean-code        × 4  (false-positive tests)

Total: 22 fixtures. All snippets are 4-15 lines each.
"""

BENCH: list[dict] = [
    # ═══════════ SQL Injection (5) ═══════════
    {
        "name": "sqli_fstring_sqlite",
        "cve": "CVE-2021-31535_INVENTED_",
        "source": (
            "import sqlite3\n"
            "def get_user(uid):\n"
            "    conn = sqlite3.connect('db.sqlite')\n"
            "    cur = conn.cursor()\n"
            "    query = f\"SELECT * FROM users WHERE id = {uid}\"\n"
            "    cur.execute(query)\n"
            "    return cur.fetchone()\n"
        ),
        "expected_findings": [
            {"syndrome": "Blind_Trust_SQLi", "line": 5, "min_verdict": "TRUTH"},
        ],
    },
    {
        "name": "sqli_fstring_pg_join",
        "cve": "CVE-2022-JOIN_INVENTED_",
        "source": (
            "def search(name):\n"
            "    return f\"SELECT * FROM products WHERE name = '{name}'\"\n"
        ),
        "expected_findings": [
            {"syndrome": "Blind_Trust_SQLi", "line": 2, "min_verdict": "TRUTH"},
        ],
    },
    {
        "name": "sqli_fstring_orm_raw",
        "cve": "CVE-2020-12345_INVENTED_",
        "source": (
            "def raw_orders(user_input):\n"
            "    q = f\"SELECT * FROM orders WHERE customer = '{user_input}'\"\n"
            "    return q\n"
        ),
        "expected_findings": [
            {"syndrome": "Blind_Trust_SQLi", "line": 2, "min_verdict": "TRUTH"},
        ],
    },
    {
        "name": "sqli_fstring_delete",
        "cve": "CVE-2023-DEL_INVENTED_",
        "source": (
            "def purge(tbl, days):\n"
            "    q = f\"DELETE FROM {tbl} WHERE created < NOW() - INTERVAL '{days} days'\"\n"
            "    return q\n"
        ),
        "expected_findings": [
            {"syndrome": "Blind_Trust_SQLi", "line": 2, "min_verdict": "TRUTH"},
        ],
    },
    {
        "name": "sqli_negative_parameterized",
        "cve": "N/A",
        "source": (
            "import sqlite3\n"
            "def safe_lookup(uid):\n"
            "    cur = sqlite3.connect('db').cursor()\n"
            "    cur.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"
            "    return cur.fetchone()\n"
        ),
        "expected_findings": [],
        "notes": "correctly parameterized — must not flag SQLi",
    },

    # ═══════════ Network_Blindspot (3) ═══════════
    {
        "name": "net_requests_no_timeout",
        "cve": "CVE-2021-35465_INVENTED_",
        "source": (
            "import requests\n"
            "def fetch(url):\n"
            "    r = requests.get(url)\n"
            "    return r.text\n"
        ),
        "expected_findings": [
            {"syndrome": "Network_Blindspot", "line": 3, "min_verdict": "LIKELY"},
        ],
    },
    {
        "name": "net_httpx_no_timeout",
        "cve": "CVE-2023-HTTPX_INVENTED_",
        "source": (
            "import httpx\n"
            "def ping():\n"
            "    return httpx.get('http://svc.internal/health')\n"
        ),
        "expected_findings": [
            {"syndrome": "Network_Blindspot", "line": 3, "min_verdict": "LIKELY"},
        ],
    },
    {
        "name": "net_negative_has_timeout",
        "cve": "N/A",
        "source": (
            "import requests\n"
            "def fetch(url):\n"
            "    return requests.get(url, timeout=5)\n"
        ),
        "expected_findings": [],
        "notes": "timeout is present — must not flag Network_Blindspot",
    },

    # ═══════════ Selective_Mutism (2) ═══════════
    {
        "name": "mutism_bare_except",
        "cve": "CVE-2019-BARE_INVENTED_",
        "source": (
            "def run():\n"
            "    try:\n"
            "        do_work()\n"
            "    except:\n"
            "        pass\n"
        ),
        "expected_findings": [
            {"syndrome": "Selective_Mutism", "line": 4, "min_verdict": "TRUTH"},
            {"syndrome": "Suppression",      "line": 4, "min_verdict": "TRUTH"},
        ],
    },
    {
        "name": "mutism_baseexception",
        "cve": "CVE-2020-BASE_INVENTED_",
        "source": (
            "def run():\n"
            "    try:\n"
            "        loop_forever()\n"
            "    except BaseException:\n"
            "        pass\n"
        ),
        "expected_findings": [
            {"syndrome": "Selective_Mutism", "line": 4, "min_verdict": "TRUTH"},
            {"syndrome": "Suppression",      "line": 4, "min_verdict": "TRUTH"},
        ],
    },

    # ═══════════ Hoarding (2) ═══════════
    {
        "name": "hoard_open_no_close",
        "cve": "CVE-HOARD1_INVENTED_",
        "source": (
            "def read_secret():\n"
            "    f = open('/etc/secret')\n"
            "    return f.read()\n"
        ),
        "expected_findings": [
            {"syndrome": "Hoarding", "line": 2, "min_verdict": "LIKELY"},
        ],
    },
    {
        "name": "hoard_negative_with_open",
        "cve": "N/A",
        "source": (
            "def read_ok():\n"
            "    with open('/etc/motd') as f:\n"
            "        return f.read()\n"
        ),
        "expected_findings": [],
        "notes": "context manager releases handle — clean",
    },

    # ═══════════ Deafness (2) ═══════════
    {
        "name": "deaf_lambda_none",
        "cve": "CVE-DEAF1_INVENTED_",
        "source": (
            "import signal\n"
            "def install():\n"
            "    signal.signal(signal.SIGTERM, lambda *a: None)\n"
        ),
        "expected_findings": [
            {"syndrome": "Deafness", "line": 3, "min_verdict": "LIKELY"},
        ],
    },
    {
        "name": "deaf_named_empty_handler",
        "cve": "CVE-DEAF2_INVENTED_",
        "source": (
            "import signal\n"
            "def handler(sig, frame):\n"
            "    pass\n"
            "signal.signal(signal.SIGINT, handler)\n"
        ),
        "expected_findings": [
            {"syndrome": "Deafness", "line": 4, "min_verdict": "LIKELY"},
        ],
    },

    # ═══════════ Insomnia (2) ═══════════
    {
        "name": "insomnia_bare_loop",
        "cve": "CVE-INSOM1_INVENTED_",
        "source": (
            "def spin():\n"
            "    while True:\n"
            "        x = 1\n"
        ),
        "expected_findings": [
            {"syndrome": "Insomnia", "line": 2, "min_verdict": "LIKELY"},
        ],
    },
    {
        "name": "insomnia_negative_break",
        "cve": "N/A",
        "source": (
            "def poll():\n"
            "    while True:\n"
            "        if done():\n"
            "            break\n"
        ),
        "expected_findings": [],
        "notes": "break exists — must not flag Insomnia",
    },

    # ═══════════ Compulsion (1) ═══════════
    {
        "name": "compulsion_no_backoff",
        "cve": "CVE-COMPUL1_INVENTED_",
        "source": (
            "def hammer(fn):\n"
            "    for _ in range(1000):\n"
            "        try:\n"
            "            return fn()\n"
            "        except Exception:\n"
            "            continue\n"
        ),
        "expected_findings": [
            {"syndrome": "Compulsion", "line": 2, "min_verdict": "LIKELY"},
        ],
    },

    # ═══════════ Suppression alone (1) ═══════════
    {
        "name": "suppression_only",
        "cve": "CVE-SUPPRESS1_INVENTED_",
        "source": (
            "def safe_call():\n"
            "    try:\n"
            "        risky()\n"
            "    except ValueError:\n"
            "        pass\n"
        ),
        "expected_findings": [
            {"syndrome": "Suppression", "line": 4, "min_verdict": "TRUTH"},
        ],
    },

    # ═══════════ Clean fixtures (4) ═══════════
    {
        "name": "clean_pure_math",
        "cve": "N/A",
        "source": (
            "def area(w, h):\n"
            "    return w * h\n"
        ),
        "expected_findings": [],
    },
    {
        "name": "clean_context_managers",
        "cve": "N/A",
        "source": (
            "def load(path):\n"
            "    with open(path, encoding='utf-8') as f:\n"
            "        return f.read()\n"
        ),
        "expected_findings": [],
    },
    {
        "name": "clean_specific_except",
        "cve": "N/A",
        "source": (
            "def get(url):\n"
            "    import requests\n"
            "    try:\n"
            "        return requests.get(url, timeout=3).json()\n"
            "    except requests.HTTPError as e:\n"
            "        raise RuntimeError(f'fetch failed: {e}')\n"
        ),
        "expected_findings": [],
    },
    {
        "name": "clean_typed_return",
        "cve": "N/A",
        "source": (
            "def pick(default, x):\n"
            "    if x is None:\n"
            "        return default\n"
            "    return x\n"
        ),
        "expected_findings": [],
    },
]


TOTAL_FIXTURES = len(BENCH)
TOTAL_EXPECTED = sum(len(b["expected_findings"]) for b in BENCH)


if __name__ == "__main__":
    import ast
    ok = 0
    for b in BENCH:
        try:
            ast.parse(b["source"])
            ok += 1
        except SyntaxError as e:
            print(f"BAD FIXTURE {b['name']}: {e}")
    print(f"{ok}/{TOTAL_FIXTURES} fixtures parse cleanly")
    print(f"expected findings total: {TOTAL_EXPECTED}")
