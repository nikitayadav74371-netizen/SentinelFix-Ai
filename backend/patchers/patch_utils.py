"""
Shared helpers for deterministic patchers. The core primitive is
`safe_replace`: patch by exact, unique text substring rather than by line
number, so multiple patches to the same file can be composed in any order
without one patch's line-count change invalidating another's target line
number.
"""
from __future__ import annotations
from typing import Optional
import difflib


def safe_replace(content: str, old_block: str, new_block: str) -> Optional[str]:
    """Replace exactly one occurrence of old_block with new_block.
    Returns None (and changes nothing) if old_block doesn't appear exactly
    once, so callers can detect ambiguity/failure instead of silently
    corrupting the file."""
    count = content.count(old_block)
    if count != 1:
        return None
    return content.replace(old_block, new_block, 1)


def unified_diff(old: str, new: str, filename: str) -> str:
    diff = difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
    )
    return "".join(diff)


def indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip(" \t"))]
