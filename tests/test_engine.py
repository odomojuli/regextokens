"""Test suite for the scanning engine (catalog, scanner, verify, report, cli).

Secret-scanner hygiene, same rule as test_patterns.py: this file commits NO
token-shaped literals. Where a checksum-valid GitHub/npm token is needed, it is
constructed at runtime from a low-entropy body and the CRC32 computed live — the
literal token never appears in source, so it can't trip push protection.
"""
from __future__ import annotations

import json
import zlib
from pathlib import Path

import pytest

from regextokens import Confidence, load_catalog, scan_text
from regextokens import report
from regextokens.cli import main
from regextokens.verify import (
    base62_encode,
    github_npm_checksum_ok,
    jwt_decodes,
    shannon_entropy,
    verify_finding,
)

ROOT = Path(__file__).resolve().parent.parent
CATALOG = load_catalog()


# ---- helpers (runtime token construction — nothing token-shaped committed) --

def _valid_checksum_token(prefix: str = "ghp_", seed: str = "ab12CD34ef") -> str:
    """A prefix token whose 6-char base62 CRC32 checksum is correct."""
    body = (seed * 4)[:30]
    return prefix + body + base62_encode(zlib.crc32(body.encode()), 6)


def _broken_checksum_token(prefix: str = "ghp_") -> str:
    """A well-formed token whose checksum is deterministically wrong."""
    good = _valid_checksum_token(prefix)
    i = len(prefix)
    swapped = "X" if good[i] != "X" else "Y"  # mutate the body -> checksum mismatches
    return good[:i] + swapped + good[i + 1 :]


# ---- verify: base62 + CRC32 -------------------------------------------------

def test_base62_encode_pads_and_encodes():
    assert base62_encode(0, 6) == "000000"
    assert base62_encode(61, 1) == "z"
    assert base62_encode(62, 2) == "10"
    assert len(base62_encode(zlib.crc32(b"whatever"), 6)) == 6


@pytest.mark.parametrize("prefix", ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "npm_"])
def test_crc_roundtrip_accepts_valid(prefix):
    assert github_npm_checksum_ok(_valid_checksum_token(prefix)) is True


@pytest.mark.parametrize("prefix", ["ghp_", "npm_"])
def test_crc_rejects_tampered(prefix):
    assert github_npm_checksum_ok(_broken_checksum_token(prefix)) is False


def test_crc_not_applicable_returns_none():
    # No checksummed prefix -> the check doesn't apply (distinct from False).
    assert github_npm_checksum_ok("AKIA" + "A" * 16) is None


def test_crc_wrong_length_is_false():
    assert github_npm_checksum_ok("ghp_" + "A" * 20) is False


# ---- verify: JWT + entropy --------------------------------------------------

def test_jwt_decodes_valid_and_invalid():
    import base64

    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    good = f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg({'sub': '1'})}.signature"
    assert jwt_decodes(good) is True
    assert jwt_decodes("eyJub3Q.reallyjson.sig") is False
    assert jwt_decodes("not-a-jwt") is None  # not dotted-triple


def test_shannon_entropy_orders_placeholder_below_random():
    assert shannon_entropy("A" * 30) < 1.0
    assert shannon_entropy("aB3xZ9kQ2mNpV7wL4tR8sY1cD6fH0jG5") > 3.5
    assert shannon_entropy("") == 0.0


# ---- verify: verify_finding tiers ------------------------------------------

def test_verify_finding_proves_valid_checksum():
    conf, reason = verify_finding("github-pat-classic", "prefix", _valid_checksum_token())
    assert conf is Confidence.VERIFIED_OFFLINE
    assert "checksum" in reason.lower()


def test_verify_finding_rejects_bad_checksum():
    conf, _ = verify_finding("github-pat-classic", "prefix", _broken_checksum_token())
    assert conf is Confidence.REJECTED


def test_verify_finding_identifier_is_low_not_secret():
    conf, reason = verify_finding("twitter-username", "identifier", "@jack")
    assert conf is Confidence.LOW
    assert "not a secret" in reason


def test_verify_finding_entropy_split():
    hi, _ = verify_finding("aws-secret-access-key", "keyword", "x", secret="aB3xZ9kQ2mNpV7wL4tR8sY1cD6fH0jG5")
    lo, _ = verify_finding("aws-secret-access-key", "keyword", "x", secret="A" * 40)
    assert hi is Confidence.PROBABLE
    assert lo is Confidence.LOW


# ---- scanner ----------------------------------------------------------------

def test_scan_finds_and_proves_github_token():
    token = _valid_checksum_token()
    findings = list(scan_text(f"token = '{token}'", CATALOG))
    gh = [f for f in findings if f.pattern_id == "github-pat-classic"]
    assert len(gh) == 1
    assert gh[0].confidence is Confidence.VERIFIED_OFFLINE


def test_scan_drops_bad_checksum_by_default():
    # Default min_confidence=LOW filters the REJECTED tier: a bad-checksum
    # ghp_ token matches the regex but must not surface. This is the differentiator.
    token = _broken_checksum_token()
    findings = [f for f in scan_text(f"k={token}", CATALOG) if f.pattern_id == "github-pat-classic"]
    assert findings == []


def test_scan_reports_line_and_column():
    token = _valid_checksum_token()
    text = "line one\nline two\nsecret = '" + token + "'\n"
    gh = [f for f in scan_text(text, CATALOG) if f.pattern_id == "github-pat-classic"]
    assert gh and gh[0].line == 3


def test_scan_redacts_secret_in_snippet():
    token = _valid_checksum_token()
    gh = [f for f in scan_text(f"t={token}", CATALOG) if f.pattern_id == "github-pat-classic"]
    assert token not in gh[0].snippet
    assert "…" in gh[0].snippet or "*" in gh[0].snippet


def test_min_confidence_filters_identifiers():
    findings = list(scan_text("hi @jack", CATALOG, min_confidence=Confidence.PROBABLE))
    assert findings == []


def test_finding_to_dict_is_json_serializable():
    token = _valid_checksum_token()
    f = next(f for f in scan_text(f"t={token}", CATALOG) if f.pattern_id == "github-pat-classic")
    json.dumps(f.to_dict())  # must not raise
    assert f.to_dict()["confidence"] == "VERIFIED_OFFLINE"


# ---- report -----------------------------------------------------------------

@pytest.fixture
def one_finding():
    token = _valid_checksum_token()
    return [f for f in scan_text(f"t={token}", CATALOG) if f.pattern_id == "github-pat-classic"]


def test_report_human_mentions_provider(one_finding):
    out = report.human(one_finding)
    assert "GitHub" in out
    assert "1 finding" in out


def test_report_human_empty():
    assert report.human([]) == "No findings."


def test_report_json_roundtrips(one_finding):
    doc = json.loads(report.as_json(one_finding))
    assert doc["count"] == 1
    assert doc["findings"][0]["pattern_id"] == "github-pat-classic"


def test_report_sarif_is_valid(one_finding):
    doc = json.loads(report.sarif(one_finding))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "regextokens"
    assert doc["runs"][0]["results"][0]["ruleId"] == "github-pat-classic"


# ---- cli --------------------------------------------------------------------

def test_cli_version_exit0(capsys):
    assert main(["version"]) == 0
    assert "regextokens" in capsys.readouterr().out


def test_cli_list_exit0(capsys):
    assert main(["list"]) == 0
    out = capsys.readouterr().out
    assert "github-pat-classic" in out


def test_cli_scan_clean_file_exit0(tmp_path, capsys):
    p = tmp_path / "clean.txt"
    p.write_text("nothing secret here, just prose.\n")
    assert main(["scan", str(p)]) == 0
    assert "No findings" in capsys.readouterr().out


def test_cli_scan_finds_secret_exit1(tmp_path, capsys):
    p = tmp_path / "leak.env"
    p.write_text("GITHUB_TOKEN=" + _valid_checksum_token() + "\n")
    assert main(["scan", str(p)]) == 1
    assert "proven" in capsys.readouterr().out


def test_cli_scan_bad_checksum_is_clean_exit0(tmp_path, capsys):
    # A regex-matching but checksum-broken token must not fail the scan.
    p = tmp_path / "fake.env"
    p.write_text("GITHUB_TOKEN=" + _broken_checksum_token() + "\n")
    assert main(["scan", str(p)]) == 0


def test_cli_scan_missing_path_exit2(capsys):
    assert main(["scan", "/no/such/path/here"]) == 2
    assert "no such file" in capsys.readouterr().err


def test_cli_scan_json_format(tmp_path, capsys):
    p = tmp_path / "leak.env"
    p.write_text("GITHUB_TOKEN=" + _valid_checksum_token() + "\n")
    main(["scan", str(p), "-f", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["count"] >= 1


# ---- bundled catalog sync ---------------------------------------------------

def test_bundled_catalog_in_sync_with_root():
    root = json.loads((ROOT / "patterns.json").read_text())
    bundled = json.loads((ROOT / "regextokens" / "data" / "patterns.json").read_text())
    assert root == bundled, "regextokens/data/patterns.json drifted from root (run build_patterns.py)"


def test_bundled_catalog_ships_no_samples():
    bundled = json.loads((ROOT / "regextokens" / "data" / "patterns.json").read_text())
    for p in bundled["patterns"]:
        assert "examples" not in p and "non_examples" not in p
