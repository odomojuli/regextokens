# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A sourced, tested token-scanning suite: a catalog of regex patterns for OAuth/API tokens and secrets (`109` patterns / `64` providers), plus an installable engine that scans files and scores each hit with **offline proof**. The core principle is that every pattern is **sourced** (primary provider docs), **tested** (positive + negative samples), and **proven** (RE2-compatible, ReDoS-checked). The engine extends "proven" to individual findings: a GitHub/npm CRC32 checksum can confirm or *reject* a match with certainty, no network.

## Commands

```
pip install -e .            # install package + `regextokens` console script
pip install pytest          # test dependency
pytest                      # full suite (patterns + engine)
pytest -k aws               # tests for patterns whose id contains "aws"
pytest "tests/test_patterns.py::test_positive_samples_match[github-pat-classic]"   # one check for one pattern
python3 build_patterns.py   # validate DATA, then regenerate patterns.json + README.md + bundled copy
regextokens scan PATH... -m verified   # scan; show only offline-proven findings
regextokens scan . --write-baseline .regextokens-baseline.json   # snapshot accepted findings
regextokens scan . --baseline .regextokens-baseline.json         # subtract them
```

## Architecture

Single source of truth is the `DATA` list in `build_patterns.py`. Everything else is generated or derived:

- `build_patterns.py` — `DATA` (all pattern entries with samples) + `validate()` + `write_json()` + `write_readme()`. Running it validates every pattern against its samples, then writes `patterns.json`, `README.md`, and a synced copy at `regextokens/data/patterns.json`.
- `patterns.json` — generated machine-readable catalog. **Never edit by hand; never add samples to it** (see invariant below).
- `README.md` — generated human reference. Never edit by hand.
- `regextokens/` — installable package that **consumes** the generated `patterns.json` (never a second definition of patterns): `catalog.py` (load/compile), `scanner.py` (walk files/text, yield `Finding`s), `verify.py` (offline proof → `Confidence` tier), `baseline.py` (fingerprints, baseline file, allowlist), `report.py` (human/JSON/SARIF), `cli.py` (`scan`/`list`/`version`). Bundles a synced copy of `patterns.json` as package data.
- `tests/test_patterns.py` — loads `build_patterns.py` via importlib (repo root is not a package) and parametrizes over every pattern id.
- `tests/test_engine.py` — scanner/verify/report/CLI tests, plus bundled-catalog sync and no-samples checks. Constructs checksum-valid tokens at runtime (never commits token literals).
- `tests/test_baseline.py` — baseline/allowlist semantics, repo-baseline honesty, distribution artifact checks, version sync.
- Distribution: `.pre-commit-hooks.yaml` (hook, default `-m probable`), `action.yml` (composite GitHub Action, SARIF out), `.github/workflows/ci.yml` (pytest matrix + self-scan dogfood) and `release.yml` (tag-triggered PyPI trusted publishing; guards tag == `__version__`). Version lives in **both** `regextokens/__init__.py` and `pyproject.toml`; `test_version_in_sync_with_pyproject` enforces sync.

### Baseline (accepted findings)

Findings carry a `fingerprint` (sha256 of pattern id + hashed secret body — line- and path-independent; never contains the secret). Suppression requires fingerprint **and** path, so the same token in a new file re-flags; line moves don't. The `allow` section of the baseline file is hand-edited policy (fnmatch path globs, pattern ids) — `--write-baseline` preserves and applies it. Tree walks skip `.regextokens-baseline.json` (explicit file targets still scan it). **The repo commits its own baseline** for the six probable-tier synthetic samples in `build_patterns.py`; `test_repo_baseline_matches_current_tree` requires it to cover the tree *exactly* — if a DATA edit adds a sample that scores `probable`, regenerate it: `regextokens scan . -m probable --write-baseline .regextokens-baseline.json`.

### Offline proof (the differentiator)

`verify.py` scores a shape match without any network call. The strongest check is the GitHub/npm CRC32: modern `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/`npm_` tokens are `prefix` + 30 base62 random + 6-char base62-encoded CRC32 of those 30 chars. `verify.github_npm_checksum_ok` recomputes it — **empirically validated against 20 real (revoked) GitHub tokens; all pass, any single-char tamper fails.** A bad checksum yields `Confidence.REJECTED` and the finding is dropped. Tiers: `verified-offline` (checksum/decoder), `probable` (structure + entropy), `low` (shape only), `rejected` (provably not a token). Never claim a key is *live* — that needs the issuer's API. When adding a checksummed provider, prove the algorithm against real revoked tokens before shipping a `REJECTED` path.

### Critical invariant: no sample tokens in committed catalog output

Sample tokens (`examples` / `non_examples`) live only in `DATA` inside `build_patterns.py` and are stripped by `write_json()`. A sample that matches a pattern also matches the issuer's secret scanner, so embedding samples in `patterns.json` would trip GitHub push protection. `test_published_catalog_ships_no_samples` enforces this. Samples must be synthetic filler (repeated `A`/`a`/`1` shapes), never real-looking credentials.

### Workflow for adding or changing a pattern

1. Edit the entry in `DATA` (`build_patterns.py`). Required fields: `id`, `provider`, `category`, `name`, `regex`, `strategy`, `examples` (≥1), `non_examples` (≥1), `refs` (≥1, primary provider documentation), `notes`.
2. Run `python3 build_patterns.py` to validate and regenerate `patterns.json`, `README.md`, and the bundled package copy.
3. Run `pytest`. `test_published_in_sync_with_source` fails if you edited DATA without regenerating; `test_bundled_catalog_in_sync_with_root` fails if the package copy drifted.

Bodies that are observed but not spec-documented (many providers call their tokens "opaque") must say so in `notes` and use a ranged quantifier (e.g. `{32,64}`) rather than false precision. Prefer primary sources; if a format can't be confirmed from one, don't ship it.

## Pattern conventions (test-enforced)

- RE2-compatible (gitleaks/Go) and Python `re`: no lookahead, no lookbehind, no backreferences (`test_re2_compatible`). The Instagram username pattern is the precedent for rewriting lookarounds into RE2-safe forms.
- Written for `re.search` (scanning embedded text), not anchored validation; `\b` brackets most tokens.
- Must not exhibit catastrophic backtracking (`test_no_catastrophic_backtracking`, 8k hostile string, <0.5s).
- `strategy` must be one of: `prefix` (distinctive prefix, reliable alone), `structure` (fixed shape), `keyword` (low entropy, gate on nearby keyword like the AWS secret key pattern), `identifier` (public, not secret), `encoding` (format validator). Keyword-gated patterns use the idiom `(?i)<keyword>[\w.\-= :'\"]{0,25}(<body>)`.
- A shape match is necessary, not sufficient — many issuers embed checksums. Notes should record deprecations, prefix collisions (e.g. Picatic vs Stripe `sk_live_`), and corrections to widely copied broken patterns.

## Gotcha (resolved)

`write_readme()` now writes `README.md` (uppercase) directly, and `main()` syncs the bundled `regextokens/data/patterns.json`. The earlier `readme.md`/`README.md` case collision is gone — do not reintroduce a lowercase `readme.md` target.

## Reference material

- `sniffer-audit.md` — audit of how major scanners (gitleaks, TruffleHog, GitHub, GitGuardian) build and verify patterns; shape-match vs live-verification tradeoff.
- `references.md` / `references.bib` — secret-detection literature. Pattern lineage traces to Meli et al., *How Bad Can It Git?* (NDSS 2019); benchmark numbers come from Basak et al. (ESEM 2023).
