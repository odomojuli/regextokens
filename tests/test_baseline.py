"""Tests for the baseline/allowlist and the distribution artifacts.

Same hygiene rule as the rest of the suite: no token-shaped literals committed;
checksum-valid tokens are constructed at runtime.
"""
from __future__ import annotations

import json
import zlib
from pathlib import Path

import pytest

import regextokens
from regextokens import Confidence, load_catalog, scan_text
from regextokens.baseline import (
    Baseline,
    DEFAULT_BASELINE_NAME,
    fingerprint,
    write_baseline,
)
from regextokens.cli import main
from regextokens.scanner import scan_path
from regextokens.verify import base62_encode

ROOT = Path(__file__).resolve().parent.parent
CATALOG = load_catalog()


def _valid_checksum_token(prefix: str = "ghp_", seed: str = "ab12CD34ef") -> str:
    body = (seed * 4)[:30]
    return prefix + body + base62_encode(zlib.crc32(body.encode()), 6)


def _leak_file(tmp_path: Path, name: str = "leak.env", seed: str = "ab12CD34ef") -> Path:
    p = tmp_path / name
    p.write_text("GITHUB_TOKEN=" + _valid_checksum_token(seed=seed) + "\n")
    return p


# ---- fingerprint ------------------------------------------------------------

def test_fingerprint_deterministic_and_discriminating():
    a = fingerprint("github-pat-classic", "sekret-body")
    assert a == fingerprint("github-pat-classic", "sekret-body")
    assert a != fingerprint("npm-token", "sekret-body")        # pattern id matters
    assert a != fingerprint("github-pat-classic", "other")     # secret matters
    assert len(a) == 32 and all(c in "0123456789abcdef" for c in a)


def test_fingerprint_never_contains_secret():
    secret = _valid_checksum_token()
    assert secret not in fingerprint("github-pat-classic", secret)


def test_finding_carries_fingerprint_and_serializes():
    token = _valid_checksum_token()
    f = next(f for f in scan_text(f"t={token}", CATALOG) if f.pattern_id == "github-pat-classic")
    assert f.fingerprint == fingerprint("github-pat-classic", token)
    assert f.to_dict()["fingerprint"] == f.fingerprint


def test_fingerprint_ignores_line_position():
    token = _valid_checksum_token()
    f1 = next(iter(scan_text(f"x={token}", CATALOG)))
    f2 = next(iter(scan_text(f"# pad\n# pad\ny = '{token}'", CATALOG)))
    assert f1.fingerprint == f2.fingerprint


# ---- baseline write / suppress roundtrip ------------------------------------

def test_write_then_suppress_roundtrip(tmp_path):
    leak = _leak_file(tmp_path)
    bl = tmp_path / DEFAULT_BASELINE_NAME
    findings = list(scan_path(leak, CATALOG))
    assert findings
    assert write_baseline(bl, findings) == len(findings)

    baseline = Baseline.load(bl)
    kept, suppressed = baseline.filter(scan_path(leak, CATALOG))
    assert kept == [] and suppressed == len(findings)


def test_suppression_survives_line_moves(tmp_path):
    leak = _leak_file(tmp_path)
    bl = tmp_path / DEFAULT_BASELINE_NAME
    write_baseline(bl, list(scan_path(leak, CATALOG)))
    leak.write_text("# new comment\n\n" + leak.read_text())  # shift the secret down
    kept, suppressed = Baseline.load(bl).filter(scan_path(leak, CATALOG))
    assert kept == [] and suppressed >= 1


def test_different_secret_not_suppressed(tmp_path):
    bl = tmp_path / DEFAULT_BASELINE_NAME
    leak = _leak_file(tmp_path)
    write_baseline(bl, list(scan_path(leak, CATALOG)))
    leak.write_text("GITHUB_TOKEN=" + _valid_checksum_token(seed="Zz9Yy8Xx7w") + "\n")
    kept, _ = Baseline.load(bl).filter(scan_path(leak, CATALOG))
    assert kept  # a new token is a new exposure


def test_same_secret_in_new_file_not_suppressed(tmp_path):
    bl = tmp_path / DEFAULT_BASELINE_NAME
    leak = _leak_file(tmp_path)
    write_baseline(bl, list(scan_path(leak, CATALOG)))
    other = _leak_file(tmp_path, name="other.env")
    kept, _ = Baseline.load(bl).filter(scan_path(other, CATALOG))
    assert kept  # path is part of the acceptance


def test_baseline_stores_no_secrets(tmp_path):
    token = _valid_checksum_token()
    leak = tmp_path / "leak.env"
    leak.write_text(f"GITHUB_TOKEN={token}\n")
    bl = tmp_path / DEFAULT_BASELINE_NAME
    write_baseline(bl, list(scan_path(leak, CATALOG)))
    text = bl.read_text()
    assert token not in text
    assert token[4:20] not in text  # not even a fragment of the body


def test_baseline_rejects_unknown_version(tmp_path):
    bl = tmp_path / DEFAULT_BASELINE_NAME
    bl.write_text(json.dumps({"version": 99, "findings": []}))
    with pytest.raises(ValueError):
        Baseline.load(bl)


# ---- allowlist --------------------------------------------------------------

def _write_allow(tmp_path, paths=(), pattern_ids=()):
    bl = tmp_path / DEFAULT_BASELINE_NAME
    bl.write_text(
        json.dumps(
            {
                "version": 1,
                "findings": [],
                "allow": {"paths": list(paths), "pattern_ids": list(pattern_ids)},
            }
        )
    )
    return bl


def test_allow_path_glob(tmp_path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    leak = _leak_file(fixtures)
    bl = _write_allow(tmp_path, paths=["fixtures/*"])
    kept, suppressed = Baseline.load(bl).filter(scan_path(leak, CATALOG))
    assert kept == [] and suppressed >= 1


def test_allow_pattern_id(tmp_path):
    leak = _leak_file(tmp_path)
    bl = _write_allow(tmp_path, pattern_ids=["github-pat-classic"])
    kept, _ = Baseline.load(bl).filter(
        f for f in scan_path(leak, CATALOG) if f.pattern_id == "github-pat-classic"
    )
    assert kept == []


def test_allow_does_not_leak_to_other_paths(tmp_path):
    leak = _leak_file(tmp_path)  # NOT under fixtures/
    bl = _write_allow(tmp_path, paths=["fixtures/*"])
    kept, _ = Baseline.load(bl).filter(scan_path(leak, CATALOG))
    assert kept


def test_write_baseline_preserves_and_applies_allow(tmp_path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    _leak_file(fixtures)
    real = _leak_file(tmp_path, name="src.env", seed="Zz9Yy8Xx7w")
    bl = _write_allow(tmp_path, paths=["fixtures/*"])

    findings = list(scan_path(tmp_path, CATALOG))
    write_baseline(bl, findings)
    doc = json.loads(bl.read_text())
    assert doc["allow"]["paths"] == ["fixtures/*"]           # hand-edited policy kept
    assert all("fixtures" not in e["path"] for e in doc["findings"])  # allowed not recorded
    assert any(e["path"] == "src.env" for e in doc["findings"])
    assert real.exists()


# ---- scanner skips the baseline file in tree walks ---------------------------

def test_tree_walk_skips_baseline_file(tmp_path):
    bl = tmp_path / DEFAULT_BASELINE_NAME
    # A baseline-shaped file whose content includes a real matchable token would
    # never be written by us; simulate any content and prove the walk skips it.
    bl.write_text("GITHUB_TOKEN=" + _valid_checksum_token() + "\n")
    assert list(scan_path(tmp_path, CATALOG)) == []
    assert list(scan_path(bl, CATALOG))  # explicit file target still scans


# ---- cli ---------------------------------------------------------------------

def test_cli_write_baseline_then_scan_clean(tmp_path, capsys):
    leak = _leak_file(tmp_path)
    bl = tmp_path / DEFAULT_BASELINE_NAME
    assert main(["scan", str(leak), "--write-baseline", str(bl)]) == 0
    assert bl.exists()
    assert main(["scan", str(leak), "--baseline", str(bl)]) == 0
    err = capsys.readouterr().err
    assert "suppressed" in err


def test_cli_baseline_and_write_baseline_mutually_exclusive(tmp_path):
    leak = _leak_file(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(leak), "--baseline", "x", "--write-baseline", "y"])
    assert exc.value.code == 2


def test_cli_missing_baseline_exit2(tmp_path, capsys):
    leak = _leak_file(tmp_path)
    assert main(["scan", str(leak), "--baseline", str(tmp_path / "nope.json")]) == 2
    assert "cannot load baseline" in capsys.readouterr().err


def test_cli_scan_multiple_paths(tmp_path, capsys):
    a = _leak_file(tmp_path, name="a.env")
    b = tmp_path / "b.txt"
    b.write_text("nothing here\n")
    assert main(["scan", str(b), str(a)]) == 1
    assert "a.env" in capsys.readouterr().out


# ---- committed repo baseline stays honest ------------------------------------

def test_repo_baseline_matches_current_tree():
    """The committed baseline must exactly cover the repo's own probable-tier
    findings (the synthetic samples in build_patterns.py) — no more, no less.
    Extra entries would mask future leaks; missing ones break the CI self-scan."""
    bl_path = ROOT / DEFAULT_BASELINE_NAME
    assert bl_path.exists(), "committed .regextokens-baseline.json is missing"
    baseline = Baseline.load(bl_path)
    findings = [
        f
        for f in scan_path(ROOT, CATALOG, min_confidence=Confidence.PROBABLE)
        if "test" not in f.path  # runtime-constructed tokens in tests/ don't exist on disk
    ]
    kept, suppressed = baseline.filter(findings)
    assert kept == [], f"unbaselined findings in repo: {[(f.path, f.line, f.pattern_id) for f in kept]}"
    n_entries = sum(len(paths) for paths in baseline.entries.values())
    assert suppressed == n_entries, "baseline has stale entries no longer present in the tree"


def test_baseline_file_itself_scans_clean():
    """Fingerprint hex in the committed baseline must not match any pattern."""
    bl_path = ROOT / DEFAULT_BASELINE_NAME
    assert list(scan_text(bl_path.read_text(), CATALOG)) == []


# ---- distribution artifacts ---------------------------------------------------

def test_precommit_hook_definition():
    text = (ROOT / ".pre-commit-hooks.yaml").read_text()
    assert "id: regextokens" in text
    assert "entry: regextokens scan" in text
    assert "language: python" in text


def test_github_action_definition():
    text = (ROOT / "action.yml").read_text()
    assert "using: composite" in text
    assert "min-confidence" in text
    assert "sarif" in text
    assert "$GITHUB_ACTION_PATH" in text  # installs this checkout, not PyPI


def test_release_workflow_guards_version():
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text()
    assert "regextokens.__version__" in text
    assert "pypa/gh-action-pypi-publish" in text


def test_version_in_sync_with_pyproject():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert f'version = "{regextokens.__version__}"' in pyproject
