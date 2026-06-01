"""
Test suite for the regextokens catalog.

Patterns and their test samples are defined in build_patterns.py (DATA). The
published catalog, patterns.json, is generated from DATA *without* the sample
tokens -- a sample that matches a pattern also matches the issuer's secret
scanner, so storing samples would trip push protection. The samples therefore
live in code and are assembled at runtime here.

Checks per pattern:
  - compiles under Python re
  - matches each positive sample, rejects each negative sample
  - RE2-compatible (no lookaround / backreferences)
  - has >=1 positive and >=1 negative sample
  - no catastrophic backtracking on a long hostile string

Plus catalog-level checks:
  - patterns.json is in sync with DATA (ids + regexes)
  - patterns.json contains NO sample strings (secret-scanner hygiene)

Run:  pytest
"""
import importlib.util
import json
import re
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Load build_patterns.py as a module (it lives at repo root, not a package).
_spec = importlib.util.spec_from_file_location("build_patterns", ROOT / "build_patterns.py")
build_patterns = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_patterns)

DATA = build_patterns.DATA
CATALOG = json.loads((ROOT / "patterns.json").read_text())
PUBLISHED = CATALOG["patterns"]

# RE2 (Go / gitleaks) supports neither lookaround nor backreferences.
RE2_FORBIDDEN = [
    (r"\(\?=", "lookahead (?=...)"),
    (r"\(\?!", "negative lookahead (?!...)"),
    (r"\(\?<=", "lookbehind (?<=...)"),
    (r"\(\?<!", "negative lookbehind (?<!...)"),
    (r"\\[1-9]", "backreference \\1-\\9"),
]

IDS = [p["id"] for p in DATA]
SAMPLE_KEYS = ("examples", "non_examples")


def _by_id(pid):
    return next(p for p in DATA if p["id"] == pid)


# ---- catalog-level ----------------------------------------------------

def test_catalog_metadata():
    for key in ("name", "generated", "flavor", "count", "patterns"):
        assert key in CATALOG, f"missing top-level key: {key}"
    assert CATALOG["count"] == len(PUBLISHED) == len(DATA)


def test_ids_unique():
    assert len(IDS) == len(set(IDS)), "duplicate pattern ids"


def test_published_in_sync_with_source():
    by_id = {p["id"]: p for p in PUBLISHED}
    assert set(by_id) == set(IDS), "patterns.json ids differ from build_patterns.DATA"
    for e in DATA:
        assert by_id[e["id"]]["regex"] == e["regex"], f"{e['id']}: regex out of sync (run build_patterns.py)"


def test_published_catalog_ships_no_samples():
    # Secret-scanner hygiene: the committed catalog must not contain sample tokens.
    for p in PUBLISHED:
        for k in SAMPLE_KEYS:
            assert k not in p, f"{p['id']}: patterns.json must not embed '{k}' (would trip secret scanners)"


def test_strategy_values_known():
    known = set(CATALOG["strategy_legend"].keys())
    for p in DATA:
        assert p["strategy"] in known, f"{p['id']}: unknown strategy {p['strategy']!r}"


# ---- per-pattern (over DATA) -----------------------------------------

@pytest.mark.parametrize("pid", IDS)
def test_compiles(pid):
    re.compile(_by_id(pid)["regex"])


@pytest.mark.parametrize("pid", IDS)
def test_required_fields(pid):
    p = _by_id(pid)
    for key in ("provider", "category", "name", "regex", "strategy", "examples", "non_examples", "refs"):
        assert key in p, f"{pid}: missing field {key}"
    assert p["examples"], f"{pid}: needs at least one positive sample"
    assert p["non_examples"], f"{pid}: needs at least one negative sample"
    assert p["refs"], f"{pid}: needs at least one source ref"


@pytest.mark.parametrize("pid", IDS)
def test_positive_samples_match(pid):
    p = _by_id(pid)
    rx = re.compile(p["regex"])
    for sample in p["examples"]:
        assert rx.search(sample), f"{pid}: positive sample did not match: {sample!r}"


@pytest.mark.parametrize("pid", IDS)
def test_negative_samples_reject(pid):
    p = _by_id(pid)
    rx = re.compile(p["regex"])
    for sample in p["non_examples"]:
        assert not rx.search(sample), f"{pid}: negative sample matched but should not: {sample!r}"


@pytest.mark.parametrize("pid", IDS)
def test_re2_compatible(pid):
    regex = _by_id(pid)["regex"]
    for probe, label in RE2_FORBIDDEN:
        assert not re.search(probe, regex), f"{pid}: uses {label}, not RE2-compatible"


@pytest.mark.parametrize("pid", IDS)
def test_no_catastrophic_backtracking(pid):
    rx = re.compile(_by_id(pid)["regex"])
    hostile = ("A" * 4000) + "!" + ("0" * 4000)
    start = time.perf_counter()
    rx.search(hostile)
    elapsed = time.perf_counter() - start
    assert elapsed < 0.5, f"{pid}: regex took {elapsed:.3f}s on an 8k string (possible ReDoS)"
