"""regextokens — a sourced, tested, offline-proving scanner for API tokens and secrets.

The pattern catalog is the single source of truth in build_patterns.py (DATA);
this package consumes the generated patterns.json and adds an engine: scanning,
offline verification, and reporting.
"""
from .baseline import Baseline, fingerprint, write_baseline
from .catalog import Pattern, load_catalog
from .scanner import Finding, scan_path, scan_text
from .verify import Confidence, verify_finding

__version__ = "0.2.0"

__all__ = [
    "Pattern",
    "load_catalog",
    "Finding",
    "scan_path",
    "scan_text",
    "Confidence",
    "verify_finding",
    "Baseline",
    "fingerprint",
    "write_baseline",
    "__version__",
]
