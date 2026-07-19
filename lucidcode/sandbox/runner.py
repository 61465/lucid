"""
LucidCode Sandbox Runner — cross-platform hardened Python execution
====================================================================

Tiered defense:
    Tier 1 : Firecracker microVM (Linux, prod)         — future work
    Tier 2 : Docker with `--network none --read-only`  — recommended
    Tier 3 : subprocess -I + timeout + wiped env       — dev fallback

The public API is one function:

    result = run_sandboxed(source_code, timeout=5, mode="auto")

`mode` values:
    "auto"       — pick strongest available (docker → subprocess)
    "docker"     — require Docker; raise if unavailable
    "subprocess" — force weakest tier (fast local dev only)

Returns a SandboxResult with `verdict`:
    "vuln_triggered" — sandbox printed VULN_TRIGGERED
    "safe"           — sandbox printed SAFE
    "timeout"        — likely infinite loop / blocking network
    "crash"          — non-zero exit outside VULN/SAFE
    "unclear"        — neither marker printed cleanly

The Fuzzer Engine reads `verdict` directly; anything other than "safe"/"unclear"
counts as a confirmation of the trauma.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Literal

Mode = Literal["auto", "docker", "subprocess"]
Verdict = Literal["vuln_triggered", "safe", "timeout", "crash", "unclear"]


# ══════════════════════════════════════════════════════════════════
# Result type
# ══════════════════════════════════════════════════════════════════
@dataclass
class SandboxResult:
    verdict: Verdict
    mode_used: str
    stdout: str
    stderr: str
    exit_code: int | None
    detail: str = ""
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def is_confirmation(self) -> bool:
        """True when Fuzzer should treat this as evidence of a trauma."""
        return self.verdict in ("vuln_triggered", "timeout", "crash")


# ══════════════════════════════════════════════════════════════════
# Docker availability probe (cached per process)
# ══════════════════════════════════════════════════════════════════
_docker_probe_result: bool | None = None


def _docker_available() -> bool:
    """Fast check: docker binary present AND daemon responsive."""
    global _docker_probe_result
    if _docker_probe_result is not None:
        return _docker_probe_result
    if not shutil.which("docker"):
        _docker_probe_result = False
        return False
    try:
        proc = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=3,
        )
        _docker_probe_result = (proc.returncode == 0 and bool(proc.stdout.strip()))
    except Exception:
        _docker_probe_result = False
    return _docker_probe_result


# ══════════════════════════════════════════════════════════════════
# Docker image + seccomp policy
# ══════════════════════════════════════════════════════════════════
_DOCKER_IMAGE = os.environ.get(
    "LUCID_SANDBOX_IMAGE", "python:3.12-slim"
)
_SECCOMP_POLICY = {
    "defaultAction": "SCMP_ACT_ERRNO",
    "syscalls": [{
        "names": [
            # minimal syscalls sufficient for python -c to run
            "read", "write", "open", "openat", "close", "exit_group", "exit",
            "rt_sigreturn", "rt_sigaction", "rt_sigprocmask",
            "brk", "mmap", "munmap", "mprotect", "madvise",
            "access", "faccessat", "faccessat2",
            "stat", "fstat", "lstat", "newfstatat",
            "lseek", "ioctl", "fcntl", "getrandom", "clock_gettime",
            "getdents64", "readlink", "readlinkat",
            "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid",
            "arch_prctl", "prctl", "set_tid_address", "set_robust_list",
            "futex", "wait4", "clone",  # python's threading/import may need clone
            "execve",  # exec into python only
            "epoll_create1", "epoll_ctl", "epoll_pwait",
            "pipe2", "dup", "dup2", "dup3",
        ],
        "action": "SCMP_ACT_ALLOW",
    }]
}


# ══════════════════════════════════════════════════════════════════
# Main API
# ══════════════════════════════════════════════════════════════════
def run_sandboxed(source: str, timeout: int = 5, mode: Mode = "auto") -> SandboxResult:
    """Execute `source` in the strongest available sandbox and classify output."""
    sb = Sandbox(timeout=timeout, mode=mode)
    return sb.run(source)


class Sandbox:
    def __init__(self, timeout: int = 5, mode: Mode = "auto") -> None:
        self.timeout = max(1, min(int(timeout), 30))
        self.mode = mode

    def run(self, source: str) -> SandboxResult:
        mode = self._resolve_mode()
        if mode == "docker":
            return self._run_docker(source)
        return self._run_subprocess(source)

    # ─── mode selection ─────────────────────────────────────────
    def _resolve_mode(self) -> str:
        if self.mode == "subprocess":
            return "subprocess"
        if self.mode == "docker":
            if not _docker_available():
                raise RuntimeError("Sandbox mode 'docker' requested but Docker daemon is not reachable")
            return "docker"
        # auto: docker only if daemon actually responds
        return "docker" if _docker_available() else "subprocess"

    # ─── docker sandbox ─────────────────────────────────────────
    def _run_docker(self, source: str) -> SandboxResult:
        with tempfile.TemporaryDirectory(prefix="lucid_sb_") as tdir:
            code_path = Path(tdir) / "code.py"
            code_path.write_text(source, encoding="utf-8")
            seccomp_path = Path(tdir) / "seccomp.json"
            seccomp_path.write_text(_json_dumps(_SECCOMP_POLICY), encoding="utf-8")

            cmd = [
                "docker", "run", "--rm",
                "--network", "none",
                "--read-only",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "--security-opt", f"seccomp={seccomp_path}",
                "--memory", "256m",
                "--pids-limit", "32",
                "--cpus", "0.5",
                "--tmpfs", "/tmp:rw,size=8m,mode=1777",
                "--tmpfs", "/work:rw,size=8m,mode=1777",
                "--workdir", "/work",
                "-v", f"{code_path.as_posix()}:/work/code.py:ro",
                _DOCKER_IMAGE,
                "python", "-I", "-B", "/work/code.py",
            ]
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=self.timeout + 3,
                )
                return _classify(
                    proc.stdout, proc.stderr, proc.returncode, mode_used="docker",
                    meta={"image": _DOCKER_IMAGE},
                )
            except subprocess.TimeoutExpired as e:
                return SandboxResult(
                    verdict="timeout", mode_used="docker",
                    stdout=(e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""),
                    stderr=(e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or ""),
                    exit_code=None,
                    detail="docker: hard timeout expired — likely infinite loop",
                    meta={"image": _DOCKER_IMAGE},
                )
            except Exception as e:
                return SandboxResult(
                    verdict="crash", mode_used="docker",
                    stdout="", stderr=str(e), exit_code=None,
                    detail=f"docker launch failed: {e}",
                )

    # ─── subprocess fallback ────────────────────────────────────
    def _run_subprocess(self, source: str) -> SandboxResult:
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write(source)
            path = f.name
        try:
            # -I : isolated mode (ignores PYTHON* env vars & user site)
            # -B : do not write .pyc
            # env wiped except PATH + SYSTEMROOT (Windows needs it)
            env = {"PATH": os.environ.get("PATH", "")}
            if sys.platform == "win32":
                env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
            proc = subprocess.run(
                [sys.executable, "-I", "-B", path],
                capture_output=True, timeout=self.timeout, env=env,
            )
            # decode with errors='replace' — child may print non-UTF8 bytes
            stdout_txt = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
            stderr_txt = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
            proc.stdout, proc.stderr = stdout_txt, stderr_txt
            return _classify(
                proc.stdout, proc.stderr, proc.returncode, mode_used="subprocess",
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(
                verdict="timeout", mode_used="subprocess",
                stdout="", stderr="", exit_code=None,
                detail="subprocess: hard timeout expired",
            )
        except Exception as e:
            return SandboxResult(
                verdict="crash", mode_used="subprocess",
                stdout="", stderr=str(e), exit_code=None,
                detail=f"subprocess launch failed: {e}",
            )
        finally:
            try: os.unlink(path)
            except OSError: pass


# ══════════════════════════════════════════════════════════════════
# Output classification
# ══════════════════════════════════════════════════════════════════
_VULN_RE = re.compile(r"\bVULN_TRIGGERED(?::([^\r\n]{0,200}))?", re.IGNORECASE)
_SAFE_RE = re.compile(r"\bSAFE\b", re.IGNORECASE)


def _classify(stdout: str, stderr: str, exit_code: int, mode_used: str,
              meta: dict | None = None) -> SandboxResult:
    combined = f"{stdout}\n{stderr}"
    m = _VULN_RE.search(combined)
    if m:
        reason = (m.group(1) or "").strip()
        return SandboxResult(
            verdict="vuln_triggered", mode_used=mode_used,
            stdout=stdout, stderr=stderr, exit_code=exit_code,
            detail=f"trigger reason: {reason[:180]}" if reason else "VULN_TRIGGERED printed",
            meta=meta or {},
        )
    if _SAFE_RE.search(combined):
        return SandboxResult(
            verdict="safe", mode_used=mode_used,
            stdout=stdout, stderr=stderr, exit_code=exit_code,
            detail="SAFE printed by adversarial harness",
            meta=meta or {},
        )
    if exit_code and exit_code != 0:
        return SandboxResult(
            verdict="crash", mode_used=mode_used,
            stdout=stdout, stderr=stderr, exit_code=exit_code,
            detail=f"non-zero exit ({exit_code}) with no explicit verdict",
            meta=meta or {},
        )
    return SandboxResult(
        verdict="unclear", mode_used=mode_used,
        stdout=stdout, stderr=stderr, exit_code=exit_code,
        detail="no VULN/SAFE marker in output",
        meta=meta or {},
    )


# ══════════════════════════════════════════════════════════════════
# Minimal JSON helper (avoid importing json for stdlib load safety)
# ══════════════════════════════════════════════════════════════════
def _json_dumps(obj) -> str:
    import json
    return json.dumps(obj, indent=2)


if __name__ == "__main__":
    demo = textwrap.dedent("""
        import sys
        try:
            x = 1 / 0
            print("SAFE")
        except ZeroDivisionError:
            print("VULN_TRIGGERED:division by zero raised as expected")
    """)
    r = run_sandboxed(demo, timeout=3, mode="auto")
    print(f"mode={r.mode_used} verdict={r.verdict}")
    print(f"detail: {r.detail}")
    print("stdout:", r.stdout[:200])
    print("stderr:", r.stderr[:200])
