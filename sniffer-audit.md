# Credential sniffer audit

An audit of how the major secret/credential scanners build and validate their
token patterns, and whether the common claim — *"their patterns are often
outdated and unverified"* — holds.

Scope: the tools, not their host platforms. Generated 2026-06-01.

## Verdict

The claim is half right, and the two halves apply to different tools.

- **Unverified** is accurate for the regex-only class: gitleaks, Nosey Parker,
  and detect-secrets in its default mode match a *shape* and stop. They never
  confirm the credential is real or live. A separate class — TruffleHog, GitHub
  secret scanning, GitGuardian — performs **live verification** (calls the
  issuer's API) and is now the precision standard. So "unverified" is a property
  of a tool's mode, not of the field.
- **Outdated** is real but concentrated. Most open lists share one ancestry (the
  NDSS 2019 "How Bad Can It Git?" patterns[^meli] plus a few early gists) and are
  copied between projects far more often than they are re-verified against current
  token formats. Staleness lives in that copied long tail. The actively maintained
  cores (gitleaks, GitHub) are not broadly stale; GitHub deliberately ships only
  current token versions.

Net: directionally correct for the copy-propagated regex lists; oversimplified
for the maintained, verifying tools. A shape match is necessary, not sufficient.

## Tools

| Tool | Type | Rules / detectors | Match method | Live verification | FP control |
|---|---|---|---|---|---|
| TruffleHog | OSS (Truffle Security) | 700+ | regex prefilter then verify | Yes — calls vendor API | verification (verified/unverified/unknown) |
| gitleaks | OSS | 150+ regex (RE2) | regex, optional entropy | No | allowlist / stopwords |
| detect-secrets | OSS (Yelp) | ~20 plugins | entropy-centric + few regex + keyword | Opt-in per plugin (e.g. Stripe) | baseline allowlist |
| Nosey Parker | OSS (Praetorian) | ~188 regex (Vectorscan) | high-precision regex selection | No | precision-tuned rule set |
| GitHub secret scanning | Platform (GitHub) | issuer-defined (partner program) | issuer-registered patterns | Yes — validity checks + issuer verify endpoint | push protection uses only current token versions |
| GitGuardian / ggshield | Commercial + OSS client | 450+ detectors | regex + context + validity | Yes — validity checks | ML + context |

Newer entrants (Praetorian Titus, ~487 rules; Kingfisher) pair Vectorscan regex
with live validation, i.e. the regex-only OSS tools are converging on the
verifying model.

## Problem 1 — verification gap

Pattern match answers "does this look like a token?" Verification answers "is
this a real, live token?" Only the second eliminates the dominant false-positive
class: revoked, fake, or example credentials that still match the shape.

- TruffleHog: an AWS key triggers `GetCallerIdentity`; a Stripe key hits a test
  endpoint; a Slack token calls the Slack API. Only successful responses are
  marked `verified`.
- GitHub: registered partner patterns are sent to the issuer's verify endpoint;
  validity checks flag active vs inactive; on a public hit the issuer is notified
  and can auto-revoke.
- gitleaks, Nosey Parker, detect-secrets (default): no network call. Output is
  shape matches, deduplicated and allowlisted, nothing more.

Consequence: a scanner with a perfect regex and no verification still drowns the
user in dead and dummy keys. This is the substantive core of the "unverified"
critique — and it is true of most open-source regex tools.

## Problem 2 — pattern staleness and shared lineage

The patterns are not independently derived. The same regexes propagate across
tools, blog posts, and gists, tracing back to a small set of sources — chiefly
Meli et al., NDSS 2019.[^meli] detect-secrets' own plugin docs cite that paper;
this repository's original list cited it eight times. Copying outpaces
re-verification, so a wrong or aged pattern survives for years across many tools.

Concrete, checkable staleness:

- **Fixed-length Stripe.** Classic lists use `(sk|rk)_live_[0-9a-zA-Z]{24}` and
  set the standard and restricted keys to the identical regex. Modern Stripe keys
  are variable length and far longer; the fixed `{24}` misses them.
- **Rigid Slack segments.** Patterns hard-coding `xoxb-[0-9]{n}-[0-9]{n}-...`
  miss valid tokens such as `xoxb-358710623633-aUGO32mVW` because segment lengths
  now vary; this drove an explicit Slack-regex fix in TruffleHog
  ([PR #3249](https://github.com/trufflesecurity/trufflehog/pull/3249)).
- **Generic OAuth secrets.** Entries like Google "OAuth secret `[0-9a-zA-Z-_]{24}`"
  match almost any 24-char string — no prefix, no anchor — so they are noise
  without a keyword gate.
- **Dead services still shipped.** Picatic (shut down 2018), Amazon MWS (retired
  for SP-API), and Facebook's fixed `EAACEdEose0cBA` app-token prefix persist in
  lists long after they stopped being issued.
- **Entropy false positives.** detect-secrets' default Base64/Hex high-entropy
  plugins flag ordinary hashes, UUIDs, and digit strings (e.g.
  [issue #693](https://github.com/Yelp/detect-secrets/issues/693)).

None of these are exotic — they are in patterns still distributed today.

## What the benchmark shows

Basak et al., *A Comparative Study of Software Secrets Reporting by Secret
Detection Tools* (ESEM 2023),[^basak] evaluated nine tools against a labeled
benchmark:

| Metric | Result |
|---|---|
| Precision (top 3) | GitHub Secret Scanner 75%, gitleaks 46%, "Commercial X" 25% |
| Recall (top) | gitleaks 88%, SpectralOps 68%, TruffleHog 52% |
| F1 (top 3) | gitleaks 60%, GitHub 48%, Commercial X 32% |
| Spread | 5 of 9 tools scored under 7% precision |
| Verdict | no tool achieved both high precision and high recall |

Reading it:

- The verifying tools win precision (GitHub 75%) but lose recall (GitHub 6%):
  they only look for known, current partner formats, so they miss everything
  else. Verification buys precision, not coverage.
- gitleaks wins recall (88%) on a wide regex net but pays in precision (46%):
  loose, plentiful patterns catch more and misfire more.
- Tool outputs barely overlap — e.g. ~18% true-positive overlap between ggshield
  and gitleaks — so "which tool is current" depends entirely on which patterns
  each happens to carry.

Caveats: the study is from 2023 on older builds (gitleaks 8.2.7, TruffleHog
3.18.0) and ran TruffleHog in `--regex --entropy` mode, not verified-only, which
understates its real-world precision. Treat the numbers as the shape of the
tradeoff, not today's exact scores.

## Maintenance signal

- gitleaks, TruffleHog, GitHub: actively maintained; GitHub ships pattern updates
  on a roughly monthly cadence (e.g. new types added March 2026).
- detect-secrets: maintained but provider-pattern-thin by design; leans on
  entropy and on the user's baseline.
- Community gists / "awesome secret regex" lists: effectively unmaintained and
  the primary vector for stale patterns entering other tools.

## Implications for this repo

`regextokens` is a regex **reference** — shape only, no live verification. It is
the same category as gitleaks rules or Nosey Parker, not TruffleHog. Judged by
this audit it should be positioned honestly:

- It does what shape-matching tools do, and inherits their ceiling: it cannot
  confirm a key is live. Pair it with a verifier (live API check or checksum
  validation) for production scanning to gain precision.
- Its advantage over the typical copied list is exactly the gaps named above:
  every pattern here is **tested** (pytest, 381 checks), **sourced**, **dated**,
  **RE2-portable**, and **tagged** by detection strategy — including explicit
  `keyword` / low-entropy flags where a bare regex would be noise. That is the
  discipline most lists skip, and skipping it is why they go stale unnoticed.

## Bibliography and sources

Academic works are footnoted below; full BibTeX in `references.bib`, annotated
list in `references.md`. Tools and documentation referenced:

- TruffleHog — find, verify, analyze: https://github.com/trufflesecurity/trufflehog
- How TruffleHog verifies secrets: https://trufflesecurity.com/blog/how-trufflehog-verifies-secrets
- gitleaks: https://github.com/gitleaks/gitleaks
- detect-secrets — plugins / verification: https://github.com/Yelp/detect-secrets/blob/master/docs/plugins.md
- Nosey Parker: https://github.com/praetorian-inc/noseyparker
- Praetorian Titus (regex + validation): https://github.com/praetorian-inc/titus
- GitHub — secret scanning partner program: https://docs.github.com/code-security/secret-scanning/secret-scanning-partnership-program/secret-scanning-partner-program
- GitHub — supported patterns: https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns
- GitHub — push protection: https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection

[^meli]: Meli, McNiece, Reaves. *How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories.* NDSS 2019. doi:10.14722/ndss.2019.23418. https://www.ndss-symposium.org/ndss-paper/how-bad-can-it-git-characterizing-secret-leakage-in-public-github-repositories/
[^basak]: Basak, Cox, Reaves, Williams. *A Comparative Study of Software Secrets Reporting by Secret Detection Tools.* ESEM 2023. doi:10.1109/ESEM56168.2023.10304853. arXiv:2307.00714.
