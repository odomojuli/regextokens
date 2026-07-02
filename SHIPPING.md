# Shipping regextokens as a security tool

Assessment and roadmap. Written 2026-06-11. **Updated 2026-07-02: Phases 1–3 shipped; baseline/allowlist pulled forward from Phase 4.**

## Status (2026-07-02)

Phases 1 (engine + CLI), 2 (offline proof), and 3 (distribution) are **done**, plus the Phase 4 baseline/allowlist. v0.2.0. Distribution: `.pre-commit-hooks.yaml` (default `-m probable`; `scan` now takes multiple paths so pre-commit can pass filenames), a composite GitHub Action (`action.yml`, SARIF out, env-var input passing, `fail-on-findings` toggle), CI workflow (pytest matrix 3.9/3.11/3.13 + a self-scan job that dogfoods the action against this repo), and a tag-triggered release workflow using PyPI **trusted publishing** — sdist/wheel build and `twine check` verified locally; the one manual step left is registering the trusted publisher on pypi.org (owner `odomojuli`, repo `regextokens`, workflow `release.yml`, environment `pypi`), then `git tag v0.2.0 && git push --tags`. Baseline/allowlist (`regextokens/baseline.py`): findings carry a line-independent fingerprint (sha256 of pattern id + hashed secret body — never the secret, safe to commit); `--write-baseline` snapshots accepted findings, `--baseline` subtracts them; suppression requires fingerprint *and* path, so the same token in a new file re-flags; a hand-edited `allow` section (fnmatch path globs, pattern ids) is preserved and applied on rewrite. The repo commits its own baseline covering the six probable-tier synthetic samples in `build_patterns.py`, and `test_repo_baseline_matches_current_tree` enforces exact coverage (no stale, no missing). SARIF now emits `partialFingerprints` for GitHub alert dedup. Test suite is 720 checks. Remaining from Phase 4: labeled-set benchmark (SecretBench), coverage expansion, optional `--verify-live` plugin.

## Where we started

The repo was a **catalog**, not a scanner. `DATA` in `build_patterns.py` held 71 patterns across 35 providers; running it validated each against synthetic samples and emitted `patterns.json` + `README.md`. `tests/` proved every pattern compiles, matches/rejects its samples, is RE2-portable, and survives a ReDoS probe. That is genuinely better than the copied lists most tools carry (see `sniffer-audit.md`): everything is sourced, dated, tested, and strategy-tagged.

But a catalog is a dependency, not a product. Nothing ran `regextokens` — no entry point, no way to point it at a directory, no output, no packaging. Shipping a tool needed an engine that consumes the catalog, a way to install and invoke it, and a precision story that survives contact with real repositories.

## The honest precision ceiling

`sniffer-audit.md` already names the trap. Shape-matching tools top out around 46% precision (gitleaks); verifying tools hit 75% (GitHub) but crater on recall because they only know current partner formats. A regex-only release of `regextokens` inherits the shape-match ceiling: it will flag every revoked key, dummy credential, and `AKIA...EXAMPLE` in test fixtures.

We are not going to build a TruffleHog-class live verifier in v1 (per-provider API clients, secret handling, rate limits, network egress in CI — large surface). Instead we take the **offline-proof** middle ground, which almost nobody occupies: confirm or reject a shape match using only local computation. This is the differentiator and it maps exactly onto the project's stated principle — *source, test, prove*.

What "prove offline" buys us concretely:

- **GitHub / npm checksum.** Modern GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) and npm tokens end in a 6-char base62-encoded CRC32 of the random body. We can recompute it. A string that has the prefix and length but a bad checksum is *provably* not a real token — we drop it with certainty, no network. This kills the largest false-positive class for the highest-value providers.
- **JWT decode.** Base64url-decode the header/payload; require valid JSON and an `alg`. Rejects `eyJunk.eyJunk.sig` lookalikes.
- **Entropy gate.** Shannon entropy on the secret body drops `AKIAAAAAAAAAAAAAAAAA` and templated placeholders that pass the regex.
- **Context gate.** For `keyword`-strategy patterns, confirm the gating keyword is genuinely adjacent, not coincidental.

Findings get a confidence tier — `verified-offline` (checksum passed), `probable` (structure + entropy), `low` (shape only) — so consumers can choose their precision/recall point instead of inheriting ours. We stay honest: offline proof raises precision on the providers that support it and is explicitly silent on those that don't (we never claim a key is *live* — that still needs a network verifier).

## Target architecture

Keep the single-source-of-truth discipline intact. `DATA` → `build_patterns.py` → `patterns.json` stays exactly as is. The scanner is a **consumer** of the generated `patterns.json`, never a second definition of patterns.

```
regextokens/                  # installable package
  __init__.py
  catalog.py    # load + compile patterns.json (bundled as package data)
  scanner.py    # walk files / stdin / diff, run patterns, yield Findings
  verify.py     # offline proof: crc32 (github/npm), jwt, entropy, context
  report.py     # formatters: human, JSON, SARIF
  cli.py        # `regextokens scan <path>`, `list`, `version`
  data/patterns.json   # generated copy, kept in sync by build_patterns.py
build_patterns.py         # unchanged role; also syncs the package copy
pyproject.toml            # packaging, entry point, deps
tests/                    # existing pattern tests + new scanner/verify tests
```

`build_patterns.main()` gains one line: after writing root `patterns.json`, copy it to `regextokens/data/`. Source of truth stays `DATA`; the package just carries the build output. Tests already fail if `patterns.json` drifts from `DATA`; we extend that to the bundled copy.

## Roadmap

**Phase 1 — engine + CLI (the "it's a tool now" milestone).** Package scaffold, `catalog.load()`, a `scanner` that walks a path (skipping VCS/dependency dirs; deliberate choice to scan everything else, since ignored files can still hold secrets - `.gitignore`-aware skipping and an allowlist/baseline are deferred to Phase 4), runs all compiled patterns via `re.search`, and emits findings with file/line/column and a redacted snippet. `cli.py` with `scan`, `list`, `version`; exit non-zero on findings. `pyproject.toml` with a `regextokens` entry point. Ship JSON + human output. This is the smallest thing that is actually a security tool.

**Phase 2 — offline proof (the differentiator).** `verify.py`: GitHub/npm CRC32-base62 checker, JWT decoder, Shannon-entropy gate, keyword-context confirmer. Wire confidence tiers into findings and let `--min-confidence` filter. Add per-verifier tests that compute checksums at runtime (no credential-shaped literals committed, consistent with the no-samples invariant).

**Phase 3 — distribution. [SHIPPED 2026-07-02]** SARIF output (GitHub code-scanning ingests it). A `pre-commit` hook (`.pre-commit-hooks.yaml`) and a composite GitHub Action that runs the CLI on a diff. Publish to PyPI (`regextokens` is available) with a tagged release — workflow in place, awaiting trusted-publisher registration + tag. These all wrap the Phase 1 CLI — no new core.

**Phase 4 — hardening + coverage.** Benchmark precision/recall against a labeled set (SecretBench, cited in `references.md`) so we can state a real number instead of inheriting the audit's. ~~Baseline/allowlist file for known-accepted findings~~ **[SHIPPED 2026-07-02]**. Expand `DATA` coverage (GCP service-account JSON, Azure, Slack app-level, JWT-in-env heuristics) once the harness exists to prove additions. Optional `--verify-live` plugin interface for users who do want network confirmation — designed so the offline core never depends on it.

## Risks and decisions

- **Scope creep into live verification.** Resist for the core. Offline proof is the honest, dependency-free, CI-safe product; live verification is an opt-in plugin, not the default.
- **Secret hygiene in our own tests.** New verifier tests must compute checksums at runtime rather than hardcoding valid tokens, preserving `test_published_catalog_ships_no_samples`'s spirit.
- **`readme.md` vs `README.md` case collision** (existing gotcha) — fold into packaging so the published long-description is unambiguous.
- **Performance.** 71 patterns over a large tree: compile once, consider a combined alternation prefilter or `re2`/`hyperscan` only if profiling demands it. RE2-portability is already guaranteed, so a future Go/`re2` engine remains open.
