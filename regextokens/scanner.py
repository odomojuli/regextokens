"""Scanning engine — walk text or a file tree, run the catalog, yield findings.

Consumes compiled Patterns from catalog.load_catalog(). Each match is scored by
verify.verify_finding() so callers can filter on confidence. Secrets are redacted
in the snippet by default so findings can be logged without re-leaking the token.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .baseline import fingerprint as _fingerprint
from .catalog import Pattern, load_catalog
from .verify import Confidence, verify_finding

# Directories never worth scanning; skipped during a tree walk.
_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache"}
# Read at most this many bytes per file; bigger files are treated as binary blobs.
_MAX_BYTES = 5 * 1024 * 1024


@dataclass(frozen=True)
class Finding:
    pattern_id: str
    provider: str
    name: str
    strategy: str
    path: str
    line: int
    column: int
    confidence: Confidence
    reason: str
    snippet: str  # redacted
    fingerprint: str  # stable identity (pattern id + hashed secret); see baseline.py

    def to_dict(self) -> dict:
        d = {
            "pattern_id": self.pattern_id,
            "provider": self.provider,
            "name": self.name,
            "strategy": self.strategy,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "confidence": self.confidence.name,
            "reason": self.reason,
            "snippet": self.snippet,
            "fingerprint": self.fingerprint,
        }
        return d


def _redact(text: str, start: int, end: int, keep: int = 4) -> str:
    """Return the matched line with the secret span masked to first/last `keep`."""
    secret = text[start:end]
    if len(secret) > keep * 2 + 3:
        masked = f"{secret[:keep]}…{'*' * 6}…{secret[-keep:]}"
    else:
        masked = "*" * len(secret)
    return text[:start] + masked + text[end:]


def scan_text(
    text: str,
    patterns: Iterable[Pattern],
    path: str = "<text>",
    min_confidence: Confidence = Confidence.LOW,
) -> Iterator[Finding]:
    """Yield findings for one blob of text. Lines/columns are 1-indexed."""
    # Precompute line offsets so we can map a match index to line/column.
    line_starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(i + 1)

    def locate(idx: int) -> tuple[int, int]:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= idx:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, idx - line_starts[lo] + 1

    for pat in patterns:
        for m in pat.compiled.finditer(text):
            secret = m.group(1) if pat.has_capture and m.groups() else None
            conf, reason = verify_finding(pat.id, pat.strategy, m.group(0), secret)
            if conf < min_confidence:
                continue
            line, col = locate(m.start())
            line_text = text[line_starts[line - 1]: (line_starts[line] - 1 if line < len(line_starts) else len(text))]
            rel_start = m.start() - line_starts[line - 1]
            rel_end = rel_start + (m.end() - m.start())
            yield Finding(
                pattern_id=pat.id,
                provider=pat.provider,
                name=pat.name,
                strategy=pat.strategy,
                path=path,
                line=line,
                column=col,
                confidence=conf,
                reason=reason,
                snippet=_redact(line_text, rel_start, rel_end).strip()[:200],
                fingerprint=_fingerprint(pat.id, secret if secret is not None else m.group(0)),
            )


def _is_probably_text(blob: bytes) -> bool:
    if b"\x00" in blob[:1024]:
        return False
    return True


def scan_path(
    root: str | Path,
    patterns: Iterable[Pattern] | None = None,
    min_confidence: Confidence = Confidence.LOW,
) -> Iterator[Finding]:
    """Scan a file or directory tree, skipping VCS/dependency dirs and binaries."""
    pats = list(patterns) if patterns is not None else load_catalog()
    root = Path(root)
    files: Iterable[Path]
    if root.is_file():
        files = [root]
    else:
        files = _walk(root)
    for fp in files:
        try:
            blob = fp.read_bytes()[:_MAX_BYTES]
        except (OSError, PermissionError):
            continue
        if not _is_probably_text(blob):
            continue
        text = blob.decode("utf-8", errors="replace")
        yield from scan_text(text, pats, path=str(fp), min_confidence=min_confidence)


def _walk(root: Path) -> Iterator[Path]:
    # The baseline file holds only fingerprint hashes (never secrets), but a
    # tree walk skips it so a future generic pattern can't flag our own output.
    # Pointing scan_path directly at the file still scans it — explicit wins.
    from .baseline import DEFAULT_BASELINE_NAME

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if name == DEFAULT_BASELINE_NAME:
                continue
            yield Path(dirpath) / name
