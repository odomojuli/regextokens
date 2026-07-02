"""Baseline and allowlist — suppress known-accepted findings without weakening the catalog.

A baseline is a reviewed snapshot: "we have seen these findings, they are
accepted (test fixtures, docs examples, revoked keys kept deliberately)".
Subsequent scans subtract it, so CI only fails on *new* secrets.

Design:

- Each finding carries a ``fingerprint``: sha256 over the pattern id and a
  sha256 of the secret body. The raw secret never appears in the baseline —
  committing the baseline file must not itself leak anything (same hygiene as
  the no-samples-in-catalog invariant).
- Fingerprints deliberately exclude line numbers, so editing a file above an
  accepted finding does not un-suppress it. They also exclude the path;
  instead the baseline entry records the path and suppression requires both
  fingerprint *and* path to match. The same token appearing in a *different*
  file is a new exposure and is reported.
- Paths are normalized relative to the baseline file's directory (posix
  separators), so the file works from any invocation directory and in CI.
- The ``allow`` section is hand-edited policy: fnmatch globs over normalized
  paths (``*`` crosses ``/``) and exact pattern ids. ``write_baseline``
  preserves it and applies it, so regenerating never clobbers policy and
  never records findings the policy already suppresses.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, Sequence, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, typing only
    from .scanner import Finding

BASELINE_VERSION = 1
DEFAULT_BASELINE_NAME = ".regextokens-baseline.json"


def fingerprint(pattern_id: str, secret: str) -> str:
    """Stable identity for a finding: pattern id + hashed secret body.

    Line- and path-independent (see module docstring). 32 hex chars is plenty
    against accidental collision and keeps the baseline diff-readable.
    """
    secret_digest = hashlib.sha256(secret.encode("utf-8", errors="replace")).hexdigest()
    raw = f"v{BASELINE_VERSION}\0{pattern_id}\0{secret_digest}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _normalize(path: str, anchor: Path) -> str:
    """Path as posix, relative to `anchor` when possible (else absolute posix)."""
    p = Path(path)
    try:
        resolved = p.resolve()
    except OSError:  # pragma: no cover - resolution is best-effort
        resolved = p
    try:
        return resolved.relative_to(anchor.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


@dataclass
class Baseline:
    """Loaded baseline: accepted fingerprints plus hand-edited allow rules."""

    anchor: Path                                  # directory paths are relative to
    entries: dict[str, set[str]] = field(default_factory=dict)  # fingerprint -> normalized paths
    allow_paths: tuple[str, ...] = ()
    allow_pattern_ids: tuple[str, ...] = ()

    @classmethod
    def load(cls, path: str | Path) -> "Baseline":
        p = Path(path)
        doc = json.loads(p.read_text())
        if doc.get("version") != BASELINE_VERSION:
            raise ValueError(
                f"unsupported baseline version {doc.get('version')!r} in {p} "
                f"(expected {BASELINE_VERSION})"
            )
        entries: dict[str, set[str]] = {}
        for e in doc.get("findings", ()):
            entries.setdefault(e["fingerprint"], set()).add(e["path"])
        allow = doc.get("allow", {})
        return cls(
            anchor=p.resolve().parent,
            entries=entries,
            allow_paths=tuple(allow.get("paths", ())),
            allow_pattern_ids=tuple(allow.get("pattern_ids", ())),
        )

    def allows(self, finding: "Finding") -> bool:
        """True if a hand-edited allow rule covers this finding."""
        if finding.pattern_id in self.allow_pattern_ids:
            return True
        if self.allow_paths:
            norm = _normalize(finding.path, self.anchor)
            if any(fnmatch(norm, g) for g in self.allow_paths):
                return True
        return False

    def suppresses(self, finding: "Finding") -> bool:
        """True if this finding is baselined (fingerprint + path) or allowed."""
        if self.allows(finding):
            return True
        paths = self.entries.get(finding.fingerprint)
        if not paths:
            return False
        return _normalize(finding.path, self.anchor) in paths

    def filter(self, findings: Iterable["Finding"]) -> tuple[list["Finding"], int]:
        """Split findings into (kept, suppressed_count)."""
        kept: list["Finding"] = []
        suppressed = 0
        for f in findings:
            if self.suppresses(f):
                suppressed += 1
            else:
                kept.append(f)
        return kept, suppressed


def write_baseline(path: str | Path, findings: Sequence["Finding"]) -> int:
    """Write (or refresh) a baseline file from the given findings.

    If the file already exists, its hand-edited ``allow`` section is preserved
    and applied first, so allowed findings are not redundantly recorded.
    Returns the number of findings recorded. Never stores secrets or snippets.
    """
    p = Path(path)
    allow = {"paths": [], "pattern_ids": []}
    if p.exists():
        try:
            prior = json.loads(p.read_text()).get("allow", {})
            allow["paths"] = list(prior.get("paths", ()))
            allow["pattern_ids"] = list(prior.get("pattern_ids", ()))
        except (ValueError, OSError):
            pass  # unreadable prior baseline: start clean rather than fail the write

    anchor = p.resolve().parent
    policy = Baseline(
        anchor=anchor,
        allow_paths=tuple(allow["paths"]),
        allow_pattern_ids=tuple(allow["pattern_ids"]),
    )

    recorded = []
    seen: set[tuple[str, str]] = set()
    for f in findings:
        if policy.allows(f):
            continue
        norm = _normalize(f.path, anchor)
        key = (f.fingerprint, norm)
        if key in seen:
            continue
        seen.add(key)
        recorded.append(
            {
                "fingerprint": f.fingerprint,
                "path": norm,
                "pattern_id": f.pattern_id,
                "line": f.line,  # informational only; matching ignores it
            }
        )
    recorded.sort(key=lambda e: (e["path"], e["pattern_id"], e["fingerprint"]))

    doc = {
        "version": BASELINE_VERSION,
        "generated": datetime.date.today().isoformat(),
        "findings": recorded,
        "allow": allow,
    }
    p.write_text(json.dumps(doc, indent=2) + "\n")
    return len(recorded)
