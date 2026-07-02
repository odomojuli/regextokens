# regextokens

A sourced, tested, offline-proving scanner for OAuth / API tokens and secrets. Every pattern is **sourced** (primary provider docs), **tested** (positive + negative samples), and **proven** (RE2-compatible, ReDoS-checked). Ships a CLI with confidence tiers. Source of truth is `DATA` in `build_patterns.py`; `patterns.json` and this file are generated from it.

`109` patterns / `64` providers / generated `2026-07-02`

## Install

```
pip install -e .          # console script + importable package
```

## Scan

```
regextokens scan PATH...              # walk files/dirs, report findings
regextokens scan PATH -m verified     # only offline-proven findings
regextokens scan PATH -f sarif        # SARIF for GitHub code scanning
regextokens list                      # show the catalog
```

Exit status: `0` no findings, `1` findings at/above the requested tier, `2` error. Point it at a diff or tree in CI to gate merges. Secrets are redacted in output by default.

## Baseline / allowlist

Accept reviewed findings (test fixtures, docs examples) so CI only fails on *new* secrets:

```
regextokens scan . --write-baseline .regextokens-baseline.json   # snapshot current findings
regextokens scan . --baseline .regextokens-baseline.json         # subtract them
```

The baseline stores fingerprints (`sha256` of pattern id + hashed secret body), never the secrets themselves, so it is safe to commit. Matching is line-independent — editing above an accepted finding does not un-suppress it — but the same token in a *different file* is a new exposure and is reported. A hand-edited `allow` section holds policy: fnmatch path globs and pattern ids. `--write-baseline` preserves and applies it. This repo commits its own baseline covering the synthetic samples in `build_patterns.py`; CI self-scans against it.

## Pre-commit hook and GitHub Action

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/odomojuli/regextokens
    rev: v0.2.0
    hooks:
      - id: regextokens
```

```yaml
# .github/workflows/secrets.yml
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: odomojuli/regextokens@main
        with:
          min-confidence: probable
          # baseline: .regextokens-baseline.json
      # optional: feed the SARIF to code scanning
      # - uses: github/codeql-action/upload-sarif@v3
      #   if: always()
      #   with: {sarif_file: regextokens.sarif}
```

Both default to `-m probable`: the `low` tier includes public identifiers and placeholders that would make a commit gate unusable.

## Confidence tiers

Every finding is scored by **offline proof** — local computation only, no network, no calls to the issuer. A shape match answers *"does this look like a token?"*; these checks answer *"can we prove, locally, that it is or isn't one?"* Filter with `-m/--min-confidence`.

- `verified-offline` — a checksum or decoder proves the structure is authentic (GitHub/npm CRC32; empirically validated against real revoked tokens).
- `probable` — structure plus a Shannon-entropy body consistent with a real secret.
- `low` — shape match only; may be a placeholder or public identifier.
- `rejected` — offline proof says this is provably *not* a real token (e.g. CRC32 mismatch); dropped before it reaches you.

The `rejected` tier is the differentiator: a `ghp_`/`npm_` string with a valid prefix and length but a bad checksum is dropped with certainty, killing the largest false-positive class for the highest-value providers. Offline proof never claims a key is *live* — that still needs the issuer's API.

## Develop

```
pip install pytest
pytest                     # validate every pattern + engine
python build_patterns.py   # regenerate patterns.json + README.md
```

Consume the catalog directly (no engine):

```python
import json, re
pats = json.load(open("patterns.json"))["patterns"]
rx = {p["id"]: re.compile(p["regex"]) for p in pats}
rx["github-pat-classic"].search(text)
```

## Files

- `build_patterns.py` — **source of truth** (`DATA`) + validator; rebuilds patterns.json and README.md.
- `patterns.json` — generated catalog (machine-readable). Never edit by hand.
- `regextokens/` — installable package: `catalog` (load), `scanner` (walk/match), `verify` (offline proof), `baseline` (accepted findings + allowlist), `report` (human/JSON/SARIF), `cli`. Bundles a synced copy of patterns.json.
- `.pre-commit-hooks.yaml` / `action.yml` / `.github/workflows/` — distribution: pre-commit hook, composite GitHub Action, CI + tag-triggered PyPI release (trusted publishing).
- `tests/` — `test_patterns.py` (every pattern: compile, match, RE2, ReDoS) and `test_engine.py` (scanner, verify, report, CLI, catalog sync).
- `sniffer-audit.md` — audit of other secret scanners (verification, staleness).
- `references.bib` / `references.md` — bibliography of the secret-detection literature.

## Conventions

- Flavor: RE2-compatible (gitleaks/Go) and Python `re`. No lookbehind or backreferences.
- Patterns are written for `re.search` (scanning embedded text). Wrap with `^`/`$` to use as validators.
- `\b` word boundaries bracket most tokens. Drop them if scanning inside base64 blobs.
- Strategy tag per entry: `prefix` = reliable alone; `structure` = fixed shape; `keyword` = gate on a nearby keyword; `identifier` = public, not secret; `encoding` = format check, not secret.
- A shape match is necessary, not sufficient. Many issuers embed checksums; verify before acting.[^verify]
- Example tokens in `patterns.json` are synthetic filler, not live credentials.

## References

- `sniffer-audit.md` — how major scanners build and verify patterns, with benchmark data.
- `references.bib` / `references.md` — bibliography of the secret-detection literature.
- Pattern lineage traces to Meli et al., *How Bad Can It Git?* (NDSS 2019).[^ndss]

## Index

- Generic / Crypto: Generic, age
- Cloud: Amazon MWS, Amazon Web Services, Cloudflare, DigitalOcean, Fly.io, Google, HashiCorp Terraform, HashiCorp Vault, Heroku, Microsoft Azure, Netlify, Okta, Pulumi, Tailscale, Vercel
- Source / CI: CircleCI, Docker, GitHub, GitLab, PyPI, RubyGems, npm
- AI: Anthropic, Cohere, DeepSeek, Fireworks AI, Groq, Hugging Face, Mistral AI, OpenAI, OpenRouter, Perplexity, Replicate, xAI
- Payments: PayPal / Braintree, Picatic, Shopify, Square, Stripe
- Comms: Discord, Mailchimp, Mailgun, SendGrid, Slack, Telegram, Twilio
- Social: Facebook, Foursquare, Instagram, Twitter / X
- Productivity: Airtable, Atlassian, Databricks, Datadog, Doppler, Dropbox, Grafana, Linear, Notion, Postman, Sentry, WakaTime

## Generic / Crypto

### Generic

**Base64 string** `[encoding]`

```
^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$
```

Format validator, not a secret. Standard Base64 alphabet with padding. Anchored.

src: https://datatracker.ietf.org/doc/html/rfc4648#section-4

**JSON Web Token (JWT)** `[structure]`

```
\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9/_-]{10,}\.[A-Za-z0-9/_-]{10,}
```

Three base64url segments. Header begins ey (i.e. {"). Decode to inspect; signature alone is not the secret.

src: https://datatracker.ietf.org/doc/html/rfc7519

**PEM private key block** `[prefix]`

```
-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----
```

Highest-value single indicator. Matches the header line of any PEM-encoded private key.

src: https://datatracker.ietf.org/doc/html/rfc7468

### age

**age X25519 secret key** `[structure]`

```
\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b
```

Bech32 with HRP 'AGE-SECRET-KEY-'; a 32-byte key encodes to 58 chars after the '1' separator (uppercase). Recipients (age1...) are public, not secrets. Post-quantum variant uses HRP AGE-SECRET-KEY-PQ-.

src: https://github.com/C2SP/C2SP/blob/main/age.md

## Cloud

### Amazon MWS

**Auth token (DEPRECATED API)** `[structure]`

```
\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b
```

amzn.mws.<UUID>. MWS retired in favor of SP-API (Login with Amazon tokens, prefixes Atza|/Atzr|). Original list entry was malformed.

src: https://developer-docs.amazon.com/sp-api/docs/migrating-from-amazon-mws

### Amazon Web Services

**Access key ID** `[prefix]`

```
\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b
```

20 chars. AKIA = long-term IAM key. ASIA = temporary STS/session key. Body is base32 (A-Z, 2-7).

src: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
src: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html

**Secret access key (keyword-gated)** `[keyword]`

```
(?i)aws[\w.\-= :'\"]{0,25}([A-Za-z0-9/+]{40})
```

40-char base64 body has no fixed prefix and is low entropy. Gate on an 'aws' keyword or it matches almost any 40-char token.

src: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html

### Cloudflare

**API token (keyword-gated)** `[keyword]`

```
(?i)cloudflare[\w.\-= :'\"]{0,25}([A-Za-z0-9_-]{40})
```

40-char token, no fixed prefix; gate on a 'cloudflare' keyword or it matches any 40-char string.

src: https://developers.cloudflare.com/fundamentals/api/get-started/create-token/

**Global API key (legacy, keyword-gated)** `[keyword]`

```
(?i)cloudflare[\w.\-= :'\"]{0,25}([a-f0-9]{37})
```

Legacy 37-hex global key; keyword-gated. Prefer scoped API tokens.

src: https://developers.cloudflare.com/fundamentals/api/get-started/keys/

**Origin CA key** `[prefix]`

```
\bv1\.0-[0-9a-f]{24}-[0-9a-f]{146}\b
```

Distinctive v1.0- prefix; regex-reliable.

src: https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/

### DigitalOcean

**Personal access token** `[prefix]`

```
\bdop_v1_[0-9a-f]{64}\b
```

OAuth token dor_v1_ / refresh dor_v1_ share the same shape.

src: https://docs.digitalocean.com/reference/api/create-personal-access-token/

### Fly.io

**API token / macaroon (fm2_)** `[prefix]`

```
\bfm2_[A-Za-z0-9+/=]{40,}
```

Macaroon: MsgPack-encoded, base64'd, then 'fm2_' prepended (per Fly's own repo, 'so it's easy to grep for them'). Sent as 'FlyV1 fm2_...'; multiples are comma-joined, each with its own fm2_.

src: https://fly.io/docs/security/tokens/
src: https://github.com/superfly/macaroon

### Google

**API key** `[prefix]`

```
\bAIza[0-9A-Za-z_-]{35}\b
```

39 chars total. Covers Maps, Firebase, and most GCP API keys.

src: https://cloud.google.com/docs/authentication/api-keys

**OAuth 2.0 client ID** `[prefix]`

```
\b[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com\b
```

Client ID is public, but pins config to a project. Ends in .apps.googleusercontent.com.

src: https://developers.google.com/identity/protocols/oauth2

**OAuth 2.0 client secret** `[prefix]`

```
\bGOCSPX-[0-9A-Za-z_-]{28}\b
```

Current client-secret format. Replaced the old unprefixed 24-char secret.

src: https://developers.google.com/identity/protocols/oauth2

**OAuth 2.0 access token** `[prefix]`

```
\bya29\.[0-9A-Za-z_-]+
```

Short-lived. Prefix ya29. then variable-length body.

src: https://developers.google.com/identity/protocols/oauth2

**OAuth 2.0 refresh token** `[prefix]`

```
\b1//[0-9A-Za-z_-]{43,128}\b
```

Begins 1// (note double slash). Replaces the older single-slash 1/ format.

src: https://developers.google.com/identity/protocols/oauth2

**Service account key file marker** `[structure]`

```
\"type\"\s*:\s*\"service_account\"
```

Fingerprints a GCP service-account key file. The live secret is the 'private_key' value in the same file (caught by private-key-block). Documented JSON shape includes type/private_key_id/private_key/client_email.

src: https://cloud.google.com/iam/docs/keys-create-delete

### HashiCorp Terraform

**HCP Terraform / Terraform Cloud API token** `[structure]`

```
\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{60,70}\b
```

Distinctive '.atlasv1.' infix (Atlas-era marker). One shape covers user, team, organization, audit, and agent tokens, and Terraform Enterprise; type is not distinguishable from shape.

src: https://developer.hashicorp.com/terraform/cloud-docs/api-docs/team-tokens

### HashiCorp Vault

**Service token (hvs.)** `[prefix]`

```
\bhvs\.[A-Za-z0-9_-]{24,}
```

Vault 1.10+ typed prefix: hvs.=service, hvb.=batch, hvr.=recovery (legacy s./b./r.). Vault documents tokens as opaque with '24 or more' random chars; length left open. Server-side-consistent and namespaced tokens run much longer (base64url body, hence _-).

src: https://developer.hashicorp.com/vault/docs/concepts/tokens

**Batch token (hvb.)** `[prefix]`

```
\bhvb\.[A-Za-z0-9_-]{24,}
```

Batch tokens are long encrypted blobs; the hvb. prefix is the reliable anchor.

src: https://developer.hashicorp.com/vault/docs/concepts/tokens

### Heroku

**API key (keyword-gated UUID)** `[keyword]`

```
(?i)heroku[\w.\-= :'\"]{0,25}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})
```

Legacy keys are bare UUIDs - indistinguishable from any UUID without a 'heroku' keyword. Newer keys use the HRKU- prefix.

src: https://devcenter.heroku.com/articles/platform-api-quickstart

**API key (v2)** `[prefix]`

```
\bHRKU-[0-9A-Za-z_-]{58,}\b
```

src: https://devcenter.heroku.com/articles/platform-api-quickstart

### Microsoft Azure

**Storage account access key (keyword-gated)** `[keyword]`

```
(?i)(?:AccountKey|SharedAccessKey)[\w.\-= :'\"]{0,25}([A-Za-z0-9+/]{86}==)
```

88-char base64 (86 chars + '=='), a 512-bit key. Same shape as Cosmos DB / Service Bus / Event Hubs SharedAccessKey; the keyword gate disambiguates. 'AccountKey' and 'SharedAccessKey' are Microsoft's own detection keywords.

src: https://learn.microsoft.com/en-us/purview/sit-defn-azure-storage-account-access-key
src: https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage

**Azure DevOps personal access token (keyword-gated)** `[keyword]`

```
(?i)(?:dev\.azure\.com|visualstudio\.com|azure[_ .\-]?devops|System\.AccessToken)[\w.\-= :'\"/@]{0,40}([A-Za-z0-9]{52,88})
```

New PATs are 84 chars (52 randomized); legacy PATs are 52 chars. No reliable standalone prefix, so gated on an Azure DevOps keyword. The '84 chars / 52 random' length is documented (sprint 241); the exact body charset and any embedded marker are NOT primary-documented, so this stays keyword-gated rather than a fixed-offset structural rule. Microsoft is deprecating PATs in favor of Entra tokens.

src: https://learn.microsoft.com/en-us/azure/devops/release-notes/2024/sprint-241-update
src: https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate

### Netlify

**Personal access token (nfp_)** `[prefix]`

```
\bnfp_[A-Za-z0-9_-]{36}\b
```

Nov 2023 format: nf-family prefixes nfp_ (PAT), nfc_ (CLI), nfo_ (OAuth), nfu_ (app), nfb_ (build); 40-char envelope. Pre-Nov-2023 tokens are unprefixed.

src: https://answers.netlify.com/t/change-to-the-netlify-authentication-token-format/106146

### Okta

**API token (SSWS, keyword-gated)** `[keyword]`

```
(?i)(?:okta|SSWS)[\w.\-= :'\"]{0,25}(00[A-Za-z0-9_-]{40})
```

Okta's proprietary SSWS tokens start '00' and are ~42 chars; the middle is elided in docs, so length/charset are partly empirical. Gated on the 'SSWS' scheme keyword (or 'okta'). Tokens expire after 30 idle days.

src: https://developer.okta.com/docs/guides/create-an-api-token/main/

### Pulumi

**Access token (pul-)** `[prefix]`

```
\bpul-[0-9a-f]{40}\b
```

Prefix pul- is documented; the 40-hex body is from Pulumi's earlier published example (current docs show only the prefix). Personal, org, and team tokens all share pul-.

src: https://www.pulumi.com/docs/reference/cloud-rest-api/access-tokens/

### Tailscale

**Auth / API / OAuth key (tskey-)** `[prefix]`

```
\btskey-(?:api|auth|client|scim|webhook)-[A-Za-z0-9]{6,20}-[A-Za-z0-9]{12,64}\b
```

tskey-<type>-<keyID>-<secret>; types api/auth/client/scim/webhook. Keys are case-sensitive. Segment lengths are not formally documented (ranged). Auth keys are the most commonly leaked (headless/CI use).

src: https://tailscale.com/docs/reference/key-prefixes

### Vercel

**Access token (2024+ format)** `[prefix]`

```
\bvcp_[A-Za-z0-9]{24}\b
```

Prefixed format introduced 2024. Related: vck_ (AI Gateway), cl_ (OAuth client id).

src: https://vercel.com/changelog/new-token-formats-and-secret-scanning

## Source / CI

### CircleCI

**Personal API token (CCIPAT)** `[prefix]`

```
\bCCIPAT_[1-9A-HJ-NP-Za-km-z]{20,30}_[0-9a-f]{40}\b
```

CCIPAT_<base58 id>_<40-hex>, introduced July 2023 (CCIPRJ_ for project tokens). Base58 alphabet excludes 0/O/I/l. Legacy tokens are bare 40-hex (only catchable keyword-gated).

src: https://circleci.com/changelog/new-format-for-api-access-tokens/

**Project API token (CCIPRJ)** `[prefix]`

```
\bCCIPRJ_[1-9A-HJ-NP-Za-km-z]{20,30}_[0-9a-f]{40}\b
```

Project-scoped sibling of CCIPAT_.

src: https://circleci.com/changelog/new-format-for-api-access-tokens/

### Docker

**Docker Hub personal access token** `[prefix]`

```
\bdckr_pat_[A-Za-z0-9_-]{20,64}\b
```

Prefix dckr_pat_ is documented; body length is community-observed (~27), hence the range. Sibling dckr_oat_ = organization access token. Older Hub tokens were bare UUIDs.

src: https://docs.docker.com/scout/explore/metrics-exporter/

### GitHub

**Personal access token (classic)** `[prefix]`

```
\bghp_[0-9A-Za-z]{36}\b
```

All GitHub v2 tokens carry a checksum in the body; shape match is necessary, not sufficient.

src: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens

**Personal access token (fine-grained)** `[prefix]`

```
\bgithub_pat_[0-9A-Za-z_]{82}\b
```

82 chars after the prefix (22 + '_' + 59).

src: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token

**OAuth access token** `[prefix]`

```
\bgho_[0-9A-Za-z]{36}\b
```

src: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps

**User-to-server token** `[prefix]`

```
\bghu_[0-9A-Za-z]{36}\b
```

src: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-with-a-github-app-on-behalf-of-a-user

**Server-to-server token** `[prefix]`

```
\bghs_[0-9A-Za-z]{36}\b
```

src: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app

**Refresh token** `[prefix]`

```
\bghr_[0-9A-Za-z]{36}\b
```

src: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens

### GitLab

**Personal access token** `[prefix]`

```
\bglpat-[0-9A-Za-z_-]{20}\b
```

GitLab moved all tokens to typed gl* prefixes.

src: https://docs.gitlab.com/ee/security/token_overview.html

**OAuth application secret** `[prefix]`

```
\bgloas-[0-9A-Za-z_-]{64}\b
```

src: https://docs.gitlab.com/ee/security/token_overview.html

**Pipeline trigger token** `[prefix]`

```
\bglptt-[0-9a-f]{40}\b
```

src: https://docs.gitlab.com/ee/security/token_overview.html

**Runner authentication token** `[prefix]`

```
\bglrt-[0-9A-Za-z_-]{20}\b
```

src: https://docs.gitlab.com/ee/security/token_overview.html

### PyPI

**Upload token** `[prefix]`

```
\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,1000}\b
```

Macaroon. The static segment AgEIcHlwaS5vcmc is base64 'pypi.org'.

src: https://pypi.org/help/#apitoken

### RubyGems

**API key (rubygems_)** `[prefix]`

```
\brubygems_[0-9a-f]{48}\b
```

rubygems_ + 48-hex, proven by the docs' own ~/.gem/credentials example. Pre-2021 legacy keys were bare 32-hex (only catchable via the :rubygems_api_key: YAML context).

src: https://guides.rubygems.org/api-key-scopes/

### npm

**Access token** `[prefix]`

```
\bnpm_[0-9A-Za-z]{36}\b
```

Prefix introduced 2021; final chars encode a CRC32 checksum.

src: https://docs.npmjs.com/about-access-tokens

## AI

### Anthropic

**API key** `[prefix]`

```
\bsk-ant-api03-[0-9A-Za-z_-]{93}AA\b
```

Body is fixed length and ends in AA.

src: https://docs.anthropic.com/en/api/getting-started

**Admin API key** `[prefix]`

```
\bsk-ant-admin01-[0-9A-Za-z_-]{93}AA\b
```

src: https://docs.anthropic.com/en/api/administration

### Cohere

**API key (keyword-gated)** `[keyword]`

```
(?i)cohere[\w.\-= :'\"]{0,25}([A-Za-z0-9]{40})
```

Cohere documents no key format (only 'BEARER [API_KEY]'). The 40-alnum body is observed-only; keyword-gated.

src: https://docs.cohere.com/reference/about

### DeepSeek

**API key (keyword-gated)** `[keyword]`

```
(?i)deepseek[\w.\-= :'\"]{0,25}(sk-[A-Za-z0-9]{24,64})
```

DeepSeek keys are sk-prefixed and collide fully with OpenAI (and partially OpenRouter) sk-. Keyword gate is mandatory, mirroring the AWS secret-key precedent. Body length empirical.

src: https://api-docs.deepseek.com/

### Fireworks AI

**API key (keyword-gated fw_)** `[keyword]`

```
(?i)fireworks[\w.\-= :'\"]{0,25}(fw_[A-Za-z0-9]{16,48})
```

Prefix fw_ is documented but short and collision-prone (fw_version...); keyword-gated rather than shipped as a bare prefix. Body length empirical (docs example is truncated).

src: https://docs.fireworks.ai/tools-sdks/python-client/the-tutorial

### Groq

**API key (gsk_)** `[prefix]`

```
\bgsk_[A-Za-z0-9]{32,64}\b
```

Prefix gsk_ documented in Groq's own examples; body length community-observed (~52), hence the range.

src: https://console.groq.com/docs/production-readiness/security-onboarding

### Hugging Face

**User access token** `[prefix]`

```
\bhf_[0-9A-Za-z]{34}\b
```

src: https://huggingface.co/docs/hub/security-tokens

**Organization API token (legacy, api_org_)** `[prefix]`

```
\bapi_org_[A-Za-z0-9]{16,48}\b
```

Legacy org token (deprecated and blocked in the huggingface_hub client). Current tokens use hf_. Kept for historical scanning of old leaks. Body length undocumented.

src: https://huggingface.co/docs/api-inference/quicktour

### Mistral AI

**API key (keyword-gated)** `[keyword]`

```
(?i)mistral[\w.\-= :'\"]{0,25}([A-Za-z0-9]{32})
```

Mistral documents no prefix, length, or format (keys are opaque). The 32-alnum body is observed-only; keyword-gated to stay usable.

src: https://docs.mistral.ai/getting-started/quickstarts/

### OpenAI

**API key** `[prefix]`

```
\bsk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{20,74}T3BlbkFJ[0-9A-Za-z_-]{20,74}\b
```

Modern keys embed the literal T3BlbkFJ (base64 'OpenAI') mid-token. Optional sub-prefixes proj-/svcacct-/admin-.

src: https://platform.openai.com/docs/api-reference/authentication

**API key (legacy, no longer issued)** `[prefix]`

```
\bsk-[0-9A-Za-z]{48}\b
```

Pre-2024 format. High false-positive rate (any sk- + 48 alnum). Prefer the T3BlbkFJ-anchored rule above.

src: https://platform.openai.com/docs/api-reference/authentication

### OpenRouter

**API key (sk-or-v1-)** `[prefix]`

```
\bsk-or-v1-[A-Za-z0-9_-]{32,128}\b
```

Distinctive sk-or-v1- prefix distinguishes from OpenAI sk-; match this before any generic sk- rule. Body observed as 64-hex; ranged to avoid false precision.

src: https://openrouter.ai/docs/api/reference/authentication

### Perplexity

**API key (pplx-)** `[prefix]`

```
\bpplx-[A-Za-z0-9]{32,64}\b
```

Prefix pplx- also appears in Perplexity model/product names (pplx-api, pplx-70b-*); the 32-char floor prevents matching those. Body length empirical.

src: https://docs.perplexity.ai/guides/api-key-management

### Replicate

**API token (r8_)** `[prefix]`

```
\br8_[A-Za-z0-9]{35,40}\b
```

Prefix r8_; body length (~37) inferred from a length-preserving mask in Replicate's docs (r8_Hw + 35 masked chars), hence the range.

src: https://replicate.com/docs/reference/http

### xAI

**API key (xai-)** `[prefix]`

```
\bxai-[A-Za-z0-9]{60,120}\b
```

Prefix xai- is solid; docs example is ~84 chars (~80 body). Exact length not formally documented, hence the range.

src: https://docs.x.ai/docs/api-reference

## Payments

### PayPal / Braintree

**Access token** `[structure]`

```
\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b
```

Dollar-delimited: access_token$production$<16>$<32>. The mangled entry in older lists never compiled.

src: https://developer.paypal.com/braintree/docs/guides/authorization/gateway-credentials

**Tokenization key (publishable)** `[prefix]`

```
\b(?:production|sandbox)_[0-9a-z]{8}_[0-9a-z]{16,}\b
```

Environment-prefixed and publishable (client-side, not a secret) - like Stripe pk_.

src: https://developer.paypal.com/braintree/docs/guides/authorization/tokenization-key

### Picatic

**API key (DEPRECATED service)** `[prefix]`

```
\bsk_live_[0-9a-z]{32}\b
```

Picatic shut down in 2018. Kept for historical scanning only. Note the prefix collides with Stripe-style sk_live_.

src: https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf

### Shopify

**Admin API access token** `[prefix]`

```
\bshpat_[0-9a-fA-F]{32}\b
```

shpat_ = admin API. Related prefixes: shpss_ (shared secret), shppa_ (private app), shpca_ (custom app).

src: https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens

**Shared secret** `[prefix]`

```
\bshpss_[0-9a-fA-F]{32}\b
```

src: https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens

**Private app access token** `[prefix]`

```
\bshppa_[0-9a-fA-F]{32}\b
```

src: https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens

**Custom app access token** `[prefix]`

```
\bshpca_[0-9a-fA-F]{32}\b
```

src: https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens

### Square

**Production access token** `[prefix]`

```
\bEAAA[0-9A-Za-z_-]{60}\b
```

Current OAuth/personal access token format.

src: https://developer.squareup.com/docs/build-basics/access-tokens

**Access token (legacy)** `[prefix]`

```
\bsq0atp-[0-9A-Za-z_-]{22}\b
```

Prefix is sq-zero-atp. The capital-O 'sqOatp' in older lists is wrong.

src: https://developer.squareup.com/docs/build-basics/access-tokens

**OAuth secret (legacy)** `[prefix]`

```
\bsq0csp-[0-9A-Za-z_-]{43}\b
```

Prefix is sq-zero-csp.

src: https://developer.squareup.com/docs/build-basics/access-tokens

### Stripe

**Secret / restricted key** `[prefix]`

```
\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99}\b
```

sk_ = full secret, rk_ = restricted (scoped). live/test mode. Length now variable (legacy 24, newer keys far longer).

src: https://docs.stripe.com/keys

**Publishable key** `[prefix]`

```
\bpk_(?:live|test)_[0-9A-Za-z]{24,99}\b
```

Client-side, not secret, but useful for environment fingerprinting.

src: https://docs.stripe.com/keys

**Webhook signing secret (whsec_)** `[prefix]`

```
\bwhsec_[A-Za-z0-9]{32,64}\b
```

HMAC signing secret (verify-only, but still sensitive: it lets an attacker forge webhook events). Prefix documented; body length empirical (32 dashboard, up to 64 from `stripe listen`).

src: https://docs.stripe.com/webhooks

## Comms

### Discord

**Bot token** `[structure]`

```
\b[MNO][0-9A-Za-z_-]{23,25}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27,38}\b
```

Three dot-separated base64url segments; first encodes the bot user ID. Approximate; verify by decoding segment 1.

src: https://discord.com/developers/docs/topics/oauth2

### Mailchimp

**API key** `[structure]`

```
\b[0-9a-f]{32}-us[0-9]{1,2}\b
```

Trailing -us<dc> is the datacenter. The 32-hex prefix alone is not distinctive.

src: https://mailchimp.com/developer/marketing/guides/quick-start/

### Mailgun

**Private API key** `[prefix]`

```
\bkey-[0-9a-f]{32}\b
```

src: https://documentation.mailgun.com/docs/mailgun/api-reference/authentication/

### SendGrid

**API key** `[prefix]`

```
\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b
```

SG.<22>.<43>

src: https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys

### Slack

**Bot token (xoxb)** `[prefix]`

```
\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9A-Za-z]{24,34}\b
```

Segment lengths are now variable; fixed {11}-{11}-{24} from older lists misses current tokens.

src: https://api.slack.com/authentication/token-types

**User token (xoxp)** `[prefix]`

```
\bxoxp-(?:[0-9]{10,13}-){3}[0-9A-Za-z]{28,34}\b
```

src: https://api.slack.com/authentication/token-types

**App configuration token (xoxe.xoxp)** `[prefix]`

```
\bxoxe\.xox[bp]-\d-[0-9A-Za-z]{146,166}\b
```

src: https://api.slack.com/authentication/rotation

**Refresh token (xoxe)** `[prefix]`

```
\bxoxe-\d-[0-9A-Za-z]{146,166}\b
```

src: https://api.slack.com/authentication/rotation

**Incoming webhook URL** `[prefix]`

```
https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,12}/B[0-9A-Za-z_]{8,12}/[0-9A-Za-z]{24}
```

Full URL is the secret. Old bare T../B../.. shape produced false positives.

src: https://api.slack.com/messaging/webhooks

**App-level token (xapp)** `[prefix]`

```
\bxapp-[0-9]-[A-Z0-9]+-[0-9]+-[0-9a-f]{40,80}\b
```

Prefix xapp- is documented (app-level tokens, Socket Mode). Segment structure (xapp-<n>-A<appid>-<digits>-<hex>) is inferred from Slack's synthetic examples plus field observation.

src: https://docs.slack.dev/authentication/tokens

### Telegram

**Bot token** `[structure]`

```
\b[0-9]{8,12}:AA[0-9A-Za-z_-]{32,34}\b
```

<bot_id>:AA<body>; body starts 'AA' (base64url). Length from the docs example ('a string, like ...'), not a hard spec. Leading \b won't match when the token is glued to the word 'bot' in api.telegram.org URLs.

src: https://core.telegram.org/bots/features

### Twilio

**Account SID** `[prefix]`

```
\bAC[0-9a-fA-F]{32}\b
```

Prefix AC + 32 hex. Older '55...' lists were incorrect.

src: https://www.twilio.com/docs/iam/api-keys

**API key SID** `[prefix]`

```
\bSK[0-9a-fA-F]{32}\b
```

Pairs with a 32-hex secret (no prefix; gate on a 'twilio' keyword).

src: https://www.twilio.com/docs/iam/api-keys

## Social

### Facebook

**Access token** `[prefix]`

```
\bEAA[0-9A-Za-z]{90,}\b
```

Graph API tokens begin EAA. The old fixed 'EAACEdEose0cBA' app prefix is obsolete.

src: https://developers.facebook.com/docs/facebook-login/guides/access-tokens

### Foursquare

**Service API key** `[prefix]`

```
\bfsq3[0-9A-Za-z/+_-]{40,}={0,2}
```

Current Places API key prefix fsq3. The old '[0-9a-zA-Z_]{5,31}' client key was too generic to detect; the original list also mis-typed it as a character class.

src: https://docs.foursquare.com/developer/reference/personalization-apis-authentication

### Instagram

**Access token** `[prefix]`

```
\bIGQ[0-9A-Za-z_-]{100,}
```

Instagram Basic Display was deprecated Dec 2024; current long-lived tokens (IGQ / Facebook EAA) are issued via the Instagram API with Facebook Login.

src: https://developers.facebook.com/docs/instagram-platform

**Username** `[identifier]`

```
(?:^|[^\w])@([A-Za-z0-9_.]{1,30})\b
```

Public handle. RE2-safe rewrite of the old lookahead-based pattern.

src: https://blog.jstassen.com/2016/03/code-regex-for-instagram-username-and-hashtags/

### Twitter / X

**App-only bearer token** `[prefix]`

```
\bA{22}[0-9A-Za-z%]{80,}
```

Begins with a long run of 'A' (base64 padding), then URL-encoded body.

src: https://developer.twitter.com/en/docs/authentication/oauth-2-0/bearer-tokens

**OAuth 1.0a access token** `[structure]`

```
\b[1-9][0-9]+-[0-9A-Za-z]{40}\b
```

<numeric user id>-<40 alnum>. Structural; pair with a 'twitter' keyword to cut noise.

src: https://developer.twitter.com/en/docs/authentication/oauth-1-0a

**Username / handle** `[identifier]`

```
(?:^|[^@\w])@(\w{1,15})\b
```

Public handle, not a secret. 1-15 word chars, not preceded by @ or word char.

src: https://github.com/twitter/twitter-text/blob/master/rb/lib/twitter-text/regex.rb

## Productivity

### Airtable

**Personal access token** `[structure]`

```
\bpat[A-Za-z0-9]{14}\.[0-9a-f]{64}\b
```

pat<14-char id>.<64-hex secret>. Airtable documents only that PATs are 'prefixed with their ID' and are otherwise opaque/variable — the '.'+64-hex body is empirical (scanner consensus). Legacy 'key'+14 API keys were deprecated Feb 2024.

src: https://airtable.com/developers/web/guides/personal-access-tokens

### Atlassian

**Cloud API token (ATATT3)** `[prefix]`

```
\bATATT3[A-Za-z0-9_=-]{100,}
```

Atlassian staff document the 'ATAT' token-prefix family (ATAT=API token, ATBB=app password, ATCT=access token); the full 'ATATT3' anchor is empirically constant. Atlassian states tokens are variable-length ('do not rely on fixed API token length'), so only the prefix is anchored. Pre-Dec-2024 tokens expired by May 2026.

src: https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/

### Databricks

**Personal access token** `[prefix]`

```
\bdapi[0-9a-f]{32}(?:-\d)?\b
```

src: https://docs.databricks.com/en/dev-tools/auth/pat.html

### Datadog

**API key (keyword-gated)** `[keyword]`

```
(?i)datadog[\w.\-= :'\"]{0,25}([a-f0-9]{32})
```

32-hex key, no prefix; gate on a 'datadog' keyword. Often paired with a 40-hex application key.

src: https://docs.datadoghq.com/account_management/api-app-keys/

**Application key (keyword-gated)** `[keyword]`

```
(?i)datadog[\w.\-= :'\"]{0,25}([a-f0-9]{40})
```

40-hex application key, no prefix; keyword-gated.

src: https://docs.datadoghq.com/account_management/api-app-keys/

### Doppler

**Personal token** `[prefix]`

```
\bdp\.pt\.[0-9A-Za-z]{43}\b
```

Other Doppler scopes use dp.st. (service), dp.sa. (service account).

src: https://docs.doppler.com/docs/service-tokens

### Dropbox

**Short-lived access token (sl.)** `[prefix]`

```
\bsl\.[A-Za-z0-9._-]{130,}
```

Short-lived (4h) OAuth tokens carry the 'sl.' prefix (Dropbox staff-confirmed); long-lived tokens are unprefixed and now deprecated. The prefix is only 3 chars, so the 130-char length floor does the disambiguation. Newer sl.u. variant adds a '.'.

src: https://developers.dropbox.com/oauth-guide

### Grafana

**Service account token (glsa_)** `[structure]`

```
\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b
```

glsa_<32 alnum>_<8-hex checksum>. Grafana added the trailing checksum specifically for scanner validation. Replaces legacy base64 API keys (eyJrIjoi...).

src: https://grafana.com/blog/new-in-grafana-9-1-service-accounts-are-now-ga/
src: https://grafana.com/docs/grafana/latest/administration/service-accounts/

**Cloud access policy token (glc_)** `[prefix]`

```
\bglc_eyJ[A-Za-z0-9+/=]{32,}
```

glc_ + base64 of a JSON payload, so the body always begins 'eyJ'. Length varies with the embedded token name. May carry base64 '=' padding (no trailing \b).

src: https://grafana.com/docs/grafana-cloud/developer-resources/api-reference/cloud-api/

### Linear

**API key** `[prefix]`

```
\blin_api_[0-9A-Za-z]{40}\b
```

src: https://developers.linear.app/docs/graphql/working-with-the-graphql-api

### Notion

**Integration token (ntn_)** `[prefix]`

```
\bntn_[A-Za-z0-9]{40,60}\b
```

ntn_ replaced the secret_ prefix for new tokens (Sept 2024), explicitly to help secret scanners. Notion advises against regex-validating tokens (treat as opaque), so body length is ranged. Legacy secret_ tokens still work.

src: https://developers.notion.com/page/changelog

### Postman

**API key (PMAK-)** `[prefix]`

```
\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b
```

PMAK-<24-hex>-<34-hex>. Prefix appears in Postman's own docs placeholders; the two-segment hex split is scanner consensus. Collection access keys use PMAT-.

src: https://learning.postman.com/docs/developer/postman-api/authentication/

### Sentry

**User auth token (sntryu_)** `[prefix]`

```
\bsntryu_[0-9a-f]{64}\b
```

sntryu_ + 64-hex (token_hex(32)). First-party prefixes: sntryu_=user, sntrys_=org, sntrya_=user-app, sntryi_=integration. Legacy tokens are bare 64-hex.

src: https://github.com/getsentry/sentry/blob/master/src/sentry/types/token.py

**Organization auth token (sntrys_)** `[prefix]`

```
\bsntrys_eyJ[A-Za-z0-9+/=]{8,}_[A-Za-z0-9+/]{43}
```

sntrys_ + base64(JSON payload, begins 'eyJ') + '_' + 43-char base64 secret (token_bytes(32), padding stripped). Exactly two underscores overall. Secret may end in +// (no trailing \b).

src: https://github.com/getsentry/sentry/blob/master/src/sentry/utils/security/orgauthtoken_token.py

### WakaTime

**API key** `[prefix]`

```
\bwaka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b
```

waka_ + UUID.

src: https://wakatime.com/developers


[^verify]: Shape-matching vs. live verification, and the staleness of copied regex lists, are examined in `sniffer-audit.md`. Full bibliography: `references.bib`, `references.md`.
[^ndss]: Meli, McNiece, Reaves. *How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories.* NDSS 2019. doi:10.14722/ndss.2019.23418.
