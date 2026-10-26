"""
GitHub source handling: validates a repo URL is reachable, clones it into
an isolated workspace folder, and validates a local path exists. When
both a local path and a GitHub URL are supplied, both are validated and
the local checkout is treated as a parity reference against the freshly
cloned copy (file list diff) so the user can see if their local copy is
out of date with the remote before scanning.
"""
from __future__ import annotations
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional, List

GITHUB_URL_RE = re.compile(
    r"^https?://github\.com/([A-Za-z0-9_.\-]+)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)


class GitValidationError(Exception):
    pass


@dataclass
class CloneResult:
    local_dir: str
    owner: str
    repo: str
    ref: Optional[str] = None


def parse_github_url(url: str) -> tuple[str, str]:
    m = GITHUB_URL_RE.match(url.strip())
    if not m:
        raise GitValidationError(
            "That doesn't look like a valid GitHub repository URL. "
            "Expected format: https://github.com/<owner>/<repo>"
        )
    return m.group(1), m.group(2)


def verify_remote_reachable(url: str, timeout: int = 20) -> None:
    """Uses `git ls-remote` to confirm the repo exists and is reachable
    without downloading its contents."""
    try:
        proc = subprocess.run(
            ["git", "ls-remote", "--exit-code", url],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        raise GitValidationError("git is not installed or not on PATH.")
    except subprocess.TimeoutExpired:
        raise GitValidationError(f"Timed out reaching {url}. Check the URL and your network connection.")
    if proc.returncode != 0:
        raise GitValidationError(
            f"Could not reach repository at {url}. "
            f"It may be private, deleted, or misspelled. (git said: {proc.stderr.strip()[:300]})"
        )


def clone_repo(url: str, workspace_dir: str, job_id: str, timeout: int = 180) -> CloneResult:
    owner, repo = parse_github_url(url)
    verify_remote_reachable(url, timeout=min(timeout, 30))

    dest = os.path.join(workspace_dir, job_id, "repo")
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(os.path.dirname(dest), exist_ok=True)

    proc = subprocess.run(
        ["git", "clone", "--depth", "1", url, dest],
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise GitValidationError(f"git clone failed: {proc.stderr.strip()[:500]}")

    if not os.path.isdir(dest) or not os.listdir(dest):
        raise GitValidationError("Cloned repository is empty.")

    return CloneResult(local_dir=dest, owner=owner, repo=repo)


def validate_local_path(path: str) -> str:
    if not path or not path.strip():
        raise GitValidationError("No local path provided.")
    path = os.path.abspath(os.path.expanduser(path.strip().strip('"')))
    if not os.path.exists(path):
        raise GitValidationError(f"Path does not exist: {path}")
    if not os.path.isdir(path):
        raise GitValidationError(f"Path is not a directory: {path}")
    if not os.listdir(path):
        raise GitValidationError(f"Directory is empty: {path}")
    return path


def compare_local_vs_clone(local_dir: str, cloned_dir: str) -> dict:
    """Lightweight parity check: relative file sets on each side."""
    def file_set(root):
        out = set()
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "venv", "__pycache__")]
            for fn in filenames:
                out.add(os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, "/"))
        return out

    local_files = file_set(local_dir)
    remote_files = file_set(cloned_dir)
    return {
        "only_in_local": sorted(local_files - remote_files),
        "only_in_remote": sorted(remote_files - local_files),
        "in_sync": local_files == remote_files,
        "local_count": len(local_files),
        "remote_count": len(remote_files),
    }
