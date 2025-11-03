#!/usr/bin/env python3
"""
Reusable venv management for PEP 723 inline script dependencies.

This module provides utilities to:
1. Parse PEP 723 inline script metadata blocks
2. Create and manage virtual environments
3. Track dependencies and reinstall when they change
"""

import contextlib
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import venv
from pathlib import Path

SCRIPT_BLOCK_RE = re.compile(r"(?m)^# /// script$\s(?P<content>(^#(| .*)$\s)+)^# ///$")


@contextlib.contextmanager
def _venv_lock(venv_dir: Path, timeout: float = 300.0):
    """
    Context manager for file-based locking of venv operations.

    Uses the .script-managed file within the venv directory for locking,
    synchronizing venv creation and pip operations across multiple processes.

    Args:
        venv_dir: Path to the virtual environment directory
        timeout: Maximum seconds to wait for lock (default: 5 minutes)
    """
    venv_dir.mkdir(parents=True, exist_ok=True)
    lock_file = venv_dir / ".script-managed"
    fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR, 0o644)

    try:
        start_time = time.time()
        locked = False

        while not locked:
            try:
                if os.name == "nt":
                    import msvcrt

                    # msvcrt.locking locks from current file position
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    locked = True
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
            except (IOError, OSError):
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    raise TimeoutError(f"Failed to acquire venv lock after {timeout}s")
                time.sleep(0.1)

        yield

    finally:
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _load_toml(text: str) -> dict:
    """Load TOML using stdlib tomllib or third-party tomli as a fallback."""
    try:
        import tomllib  # type: ignore[attr-defined]
    except Exception:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except Exception as exc:  # pragma: no cover - import error path
            raise SystemExit(
                "Missing TOML parser. Install 'tomli' or use Python >= 3.11."
            ) from exc
    return tomllib.loads(text)


def read_pep723_metadata(script_path: Path) -> dict:
    """
    Parse PEP 723 inline script metadata from a Python file.

    Returns the parsed TOML data as a dict, or empty dict if no block found.
    """
    text = script_path.read_text(encoding="utf-8")
    m = SCRIPT_BLOCK_RE.search(text)
    if not m:
        return {}
    content = m.group("content")
    toml_lines: list[str] = []
    for line in content.splitlines():
        if not line.startswith("#"):
            continue
        # Strip the leading comment marker and a single optional space
        if line.startswith("# "):
            toml_lines.append(line[2:])
        else:
            toml_lines.append(line[1:])

    toml_text = "\n".join(toml_lines)
    return _load_toml(toml_text)


def deps_digest(deps: list[str]) -> str:
    """Compute a stable hash of the dependency list."""
    return hashlib.sha256(json.dumps(sorted(deps)).encode()).hexdigest()


def in_venv() -> bool:
    """
    Check if we're currently running inside a virtual environment.
    """
    return sys.prefix != sys.base_prefix


def _parse_version_tuple(v: str) -> tuple[int, int, int]:
    """Parse a version like '3.12.1' into a 3-tuple, ignoring any suffixes."""
    parts = re.findall(r"\d+", v)
    nums = [int(p) for p in parts[:3]]
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)  # type: ignore[return-value]


def _satisfies_requires_python(
    spec: str, current: tuple[int, int, int] | None = None
) -> bool:
    """
    Minimal evaluator for PEP 440-like specifiers in requires-python.

    Supports common operators: >=, >, <=, <, ==, != and wildcard '==3.12.*'.
    Combines multiple comma-separated specifiers with logical AND.
    """
    cur = current or (
        sys.version_info.major,
        sys.version_info.minor,
        sys.version_info.micro,
    )

    def cmp(a: tuple[int, int, int], b: tuple[int, int, int]) -> int:
        return (a > b) - (a < b)

    for raw in spec.split(","):
        s = raw.strip()
        if not s:
            continue
        op = None
        for candidate in (">=", "<=", "==", "!=", ">", "<"):
            if s.startswith(candidate):
                op = candidate
                ver = s[len(candidate) :].strip()
                break
        if op is None:
            # Treat bare version as ==version (prefix match compatible with '==3.12.*')
            op, ver = "==", s
        wildcard = op in {"==", "!="} and ver.endswith(".*")
        if wildcard:
            ver = ver[:-2]
        tgt = _parse_version_tuple(ver)
        c = cmp(cur, tgt)
        if op == ">=":
            if c < 0:
                return False
        elif op == ">":
            if c <= 0:
                return False
        elif op == "<=":
            if c > 0:
                return False
        elif op == "<":
            if c >= 0:
                return False
        elif op == "==":
            if wildcard:
                # Prefix equality: compare only provided components
                prefix = _parse_version_tuple(ver)  # already trimmed
                plen = 2 if ver.count(".") == 1 else 3
                if tuple(cur[:plen]) != tuple(prefix[:plen]):
                    return False
            else:
                if c != 0:
                    return False
        elif op == "!=":
            if wildcard:
                prefix = _parse_version_tuple(ver)
                plen = 2 if ver.count(".") == 1 else 3
                if tuple(cur[:plen]) == tuple(prefix[:plen]):
                    return False
            else:
                if c == 0:
                    return False
        else:
            return False
    return True


def is_venv_managed(venv_dir: Path) -> bool:
    """Check if a venv was created by this script manager."""
    marker = venv_dir / ".script-managed"
    return marker.exists()


def get_venv_digest(venv_dir: Path) -> str | None:
    """Get the stored dependency digest from a managed venv."""
    marker = venv_dir / ".script-managed"
    if not marker.exists():
        return None
    return marker.read_text().strip()


def set_venv_digest(venv_dir: Path, digest: str) -> None:
    """Store the dependency digest in a managed venv."""
    marker = venv_dir / ".script-managed"
    marker.write_text(digest)


def create_venv(venv_dir: Path) -> Path:
    """
    Create a new virtual environment and return the path to its Python binary.

    Note: This function should be called within a _venv_lock() context.
    """
    python_bin = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python_bin.exists():
        venv.create(venv_dir, with_pip=True)
    return python_bin


def install_deps(python_bin: Path, deps: list[str]) -> None:
    """
    Install dependencies into a virtual environment.

    Note: This function should be called within a _venv_lock() context.
    """
    if not deps:
        return
    subprocess.check_call([str(python_bin), "-m", "pip", "install", *deps])


def bootstrap_venv(script_file: str) -> None:
    """
    Bootstrap the script with its venv if not already running in one.

    If script_path is None, uses __file__ from the calling context.
    This function will re-exec the script with the venv's Python if needed.
    """
    # Allow users to opt out entirely
    if os.environ.get("AUTOVENV", "1").lower() in {"0", "false", "no"}:
        return

    script_path = Path(script_file).resolve()

    # Read PEP 723 metadata
    meta = read_pep723_metadata(script_path)
    requires = meta.get("requires-python")
    if isinstance(requires, str) and not _satisfies_requires_python(requires):
        msg = (
            f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} "
            f"does not satisfy requires-python: {requires}"
        )
        raise SystemExit(msg)
    deps = meta.get("dependencies", [])
    current_digest = deps_digest(deps)

    if in_venv():
        # Already in a venv, use it
        venv_dir = Path(sys.prefix)
        python_bin = Path(sys.executable)
        managed = is_venv_managed(venv_dir)
    else:
        # Create a new managed venv
        venv_dir = script_path.parent / ".venv"
        with _venv_lock(venv_dir):
            python_bin = create_venv(venv_dir)
        managed = True

    stored_digest = get_venv_digest(venv_dir)
    if managed and stored_digest != current_digest:
        # Managed venv and deps changed, reinstall
        with _venv_lock(venv_dir):
            # Double-check pattern: another process may have just finished installing
            stored_digest = get_venv_digest(venv_dir)
            if stored_digest != current_digest:
                install_deps(python_bin, deps)
                set_venv_digest(venv_dir, current_digest)

    if venv_dir != Path(sys.prefix):
        # Re-exec with venv Python
        os.execv(str(python_bin), [str(python_bin), str(script_path), *sys.argv[1:]])
