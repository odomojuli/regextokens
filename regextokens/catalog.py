"""Load and compile the pattern catalog.

patterns.json is generated from DATA in build_patterns.py and bundled as package
data. This module never defines patterns itself — it only loads the generated
artifact, so the single-source-of-truth invariant holds.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

_BUNDLED = Path(__file__).resolve().parent / "data" / "patterns.json"
_REPO_ROOT = Path(__file__).resolve().parent.parent / "patterns.json"


@dataclass(frozen=True)
class Pattern:
    """One catalog entry with its regex pre-compiled."""

    id: str
    provider: str
    category: str
    name: str
    regex: str
    strategy: str
    refs: tuple[str, ...]
    notes: str
    compiled: re.Pattern

    @property
    def has_capture(self) -> bool:
        """Keyword-gated patterns capture the secret body in group 1."""
        return self.compiled.groups >= 1


def _catalog_path(path: str | Path | None) -> Path:
    if path is not None:
        return Path(path)
    # Prefer the bundled copy (works after pip install); fall back to repo root
    # for development checkouts before the package data is synced.
    if _BUNDLED.exists():
        return _BUNDLED
    return _REPO_ROOT


def load_catalog(path: str | Path | None = None) -> list[Pattern]:
    """Load patterns.json and return compiled Pattern objects.

    Raises FileNotFoundError if no catalog is found, re.error if a pattern in
    the catalog fails to compile (which the build step should already prevent).
    """
    catalog_path = _catalog_path(path)
    raw = json.loads(catalog_path.read_text())
    patterns: list[Pattern] = []
    for entry in raw["patterns"]:
        patterns.append(
            Pattern(
                id=entry["id"],
                provider=entry["provider"],
                category=entry["category"],
                name=entry["name"],
                regex=entry["regex"],
                strategy=entry["strategy"],
                refs=tuple(entry.get("refs", ())),
                notes=entry.get("notes", ""),
                compiled=re.compile(entry["regex"]),
            )
        )
    return patterns


def iter_catalog(path: str | Path | None = None) -> Iterator[Pattern]:
    yield from load_catalog(path)
