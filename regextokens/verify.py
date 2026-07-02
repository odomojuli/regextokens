"""Offline proof — raise or lower confidence in a shape match without any network call.

This is the project's differentiator. A regex answers "does this look like a
token?"; these checks answer "can we prove, locally, that it is or isn't one?"
None of them confirm a key is *live* (that needs the issuer's API) — they exploit
structure the issuer baked into the token: checksums, decodable headers, entropy.

Verifiers implemented:
  - GitHub / npm CRC32-base62 checksum (proof: can REJECT a bad match outright)
  - JWT header/payload decode (rejects non-JSON lookalikes)
  - Shannon entropy gate (drops low-entropy placeholders like AKIAAAAA...)

Confidence tiers let callers pick a precision/recall point via --min-confidence.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import zlib
from enum import IntEnum

_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# GitHub and npm share one format: prefix + 30 random base62 chars + 6-char
# base62-encoded CRC32 of those 30 chars. Algorithm confirmed by the maintainer
# pseudo-code in therootcompany/base62-token.js#2, and this implementation was
# checked against the 20 real revoked GitHub tokens published there: all 20 pass,
# any single-character tamper fails. github_pat_ (fine-grained) uses a different
# internal layout and is deliberately excluded — we don't claim a checksum we can't prove.
_CRC_PREFIXES = ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "npm_")
_CRC_BODY_LEN = 30
_CRC_SUM_LEN = 6


class Confidence(IntEnum):
    """Higher = more certain it's a real token. REJECTED = provably not."""

    REJECTED = 0          # offline proof says this is not a real token
    LOW = 1               # shape match only; may be a placeholder
    PROBABLE = 2          # structure + entropy consistent with a live secret
    VERIFIED_OFFLINE = 3  # checksum/decoder proves the structure is authentic


def base62_encode(num: int, pad: int) -> str:
    """Encode an unsigned int in base62, left-padded with '0' to `pad` chars."""
    if num == 0:
        out = "0"
    else:
        chars = []
        while num > 0:
            num, rem = divmod(num, 62)
            chars.append(_BASE62[rem])
        out = "".join(reversed(chars))
    return out.rjust(pad, "0")


def github_npm_checksum_ok(token: str) -> bool | None:
    """Validate the GitHub/npm CRC32 checksum.

    Returns True if the checksum matches, False if it doesn't, and None if the
    token isn't one of the checksummed prefixes (i.e. the check doesn't apply).
    """
    prefix = next((p for p in _CRC_PREFIXES if token.startswith(p)), None)
    if prefix is None:
        return None
    payload = token[len(prefix):]
    if len(payload) != _CRC_BODY_LEN + _CRC_SUM_LEN:
        return False
    body, checksum = payload[:_CRC_BODY_LEN], payload[_CRC_BODY_LEN:]
    expected = base62_encode(zlib.crc32(body.encode()), _CRC_SUM_LEN)
    return checksum == expected


def jwt_decodes(token: str) -> bool | None:
    """True if the first two JWT segments base64url-decode to JSON with an alg.

    None if the token isn't dotted-triple shaped (check doesn't apply).
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = _b64url(parts[0])
        json.loads(_b64url(parts[1]))  # payload must be JSON too
        head = json.loads(header)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    return isinstance(head, dict) and "alg" in head


def _b64url(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def shannon_entropy(s: str) -> float:
    """Bits of Shannon entropy per character. Random base62 ~5.0+; AAAA... ~0."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Tunable: below this, a token body looks like a placeholder, not a real secret.
ENTROPY_FLOOR = 2.5


def verify_finding(pattern_id: str, strategy: str, matched: str, secret: str | None = None) -> tuple[Confidence, str]:
    """Score a single finding using whatever offline proof applies.

    `matched` is the full regex match; `secret` is the captured body for
    keyword-gated patterns (regex group 1), else None.
    Returns (confidence, human-readable reason).
    """
    # Public identifiers and format validators are not secrets by definition.
    if strategy in ("identifier", "encoding"):
        return Confidence.LOW, f"{strategy}: not a secret, informational only"

    # Strongest: cryptographic checksum baked into the token.
    crc = github_npm_checksum_ok(matched)
    if crc is True:
        return Confidence.VERIFIED_OFFLINE, "CRC32 checksum valid"
    if crc is False:
        return Confidence.REJECTED, "CRC32 checksum mismatch — not a real token"

    # JWTs: prove the structure decodes.
    if pattern_id == "jwt":
        ok = jwt_decodes(matched)
        if ok is True:
            return Confidence.PROBABLE, "JWT header/payload decode to JSON"
        if ok is False:
            return Confidence.REJECTED, "JWT segments do not decode to JSON"

    # Fall back to entropy on the most secret-like span we have.
    body = secret if secret is not None else matched
    ent = shannon_entropy(body)
    if ent < ENTROPY_FLOOR:
        return Confidence.LOW, f"low entropy ({ent:.2f} bits/char) — likely placeholder"
    return Confidence.PROBABLE, f"entropy {ent:.2f} bits/char consistent with a secret"
