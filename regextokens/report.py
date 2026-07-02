"""Output formatters: human-readable, JSON, and SARIF (GitHub code-scanning)."""
from __future__ import annotations

import json
from typing import Sequence

from .scanner import Finding

_TIER_MARK = {
    "VERIFIED_OFFLINE": "[proven]",
    "PROBABLE": "[probable]",
    "LOW": "[low]",
    "REJECTED": "[rejected]",
}


def human(findings: Sequence[Finding]) -> str:
    if not findings:
        return "No findings."
    lines = []
    for f in findings:
        mark = _TIER_MARK.get(f.confidence.name, f.confidence.name)
        lines.append(f"{f.path}:{f.line}:{f.column}  {mark} {f.provider} — {f.name}")
        lines.append(f"    {f.reason}")
        lines.append(f"    {f.snippet}")
        lines.append(f"    fingerprint: {f.fingerprint}")
    n = len(findings)
    lines.append("")
    lines.append(f"{n} finding{'s' if n != 1 else ''}.")
    return "\n".join(lines)


def as_json(findings: Sequence[Finding]) -> str:
    return json.dumps({"findings": [f.to_dict() for f in findings], "count": len(findings)}, indent=2)


def sarif(findings: Sequence[Finding]) -> str:
    """Minimal SARIF 2.1.0 — ingestible by GitHub code scanning."""
    rules = {}
    results = []
    for f in findings:
        rules.setdefault(
            f.pattern_id,
            {
                "id": f.pattern_id,
                "name": f.name,
                "shortDescription": {"text": f"{f.provider} — {f.name}"},
            },
        )
        results.append(
            {
                "ruleId": f.pattern_id,
                "level": "error" if f.confidence.name == "VERIFIED_OFFLINE" else "warning",
                "message": {"text": f"{f.provider} {f.name} ({f.confidence.name}): {f.reason}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path},
                            "region": {"startLine": f.line, "startColumn": f.column},
                        }
                    }
                ],
                # Stable across line moves — lets GitHub code scanning dedup alerts.
                "partialFingerprints": {"regextokensFingerprint/v1": f.fingerprint},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "regextokens", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
