# regextokens

Regex reference for scanning OAuth / API tokens and secrets. Each entry: the pattern, a source, and caveats. Source of truth is `patterns.json`; this file is generated from it.

`71` patterns / `35` providers / generated `2026-06-01`

## Use

```
pip install pytest
pytest                 # validate every pattern against its samples
python build_patterns.py   # regenerate patterns.json + readme.md
```

Consume the catalog:

```python
import json, re
pats = json.load(open("patterns.json"))["patterns"]
rx = {p["id"]: re.compile(p["regex"]) for p in pats}
rx["github-pat-classic"].search(text)
```

## Files

- `patterns.json` — source of truth (the catalog).
- `build_patterns.py` — generator + validator; rebuilds readme.md and patterns.json.
- `tests/test_patterns.py` — pytest suite: compiles, matches, and RE2-checks every pattern.
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

- Generic / Crypto: Generic
- Cloud: Amazon MWS, Amazon Web Services, Cloudflare, DigitalOcean, Google, Heroku, Vercel
- Source / CI: GitHub, GitLab, PyPI, npm
- AI: Anthropic, Hugging Face, OpenAI
- Payments: PayPal / Braintree, Picatic, Shopify, Square, Stripe
- Comms: Discord, Mailchimp, Mailgun, SendGrid, Slack, Twilio
- Social: Facebook, Foursquare, Instagram, Twitter / X
- Productivity: Databricks, Datadog, Doppler, Linear, WakaTime

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

### Vercel

**Access token (2024+ format)** `[prefix]`

```
\bvcp_[A-Za-z0-9]{24}\b
```

Prefixed format introduced 2024. Related: vck_ (AI Gateway), cl_ (OAuth client id).

src: https://vercel.com/changelog/new-token-formats-and-secret-scanning

## Source / CI

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

### Hugging Face

**User access token** `[prefix]`

```
\bhf_[0-9A-Za-z]{34}\b
```

src: https://huggingface.co/docs/hub/security-tokens

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

### Linear

**API key** `[prefix]`

```
\blin_api_[0-9A-Za-z]{40}\b
```

src: https://developers.linear.app/docs/graphql/working-with-the-graphql-api

### WakaTime

**API key** `[prefix]`

```
\bwaka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b
```

waka_ + UUID.

src: https://wakatime.com/developers


[^verify]: Shape-matching vs. live verification, and the staleness of copied regex lists, are examined in `sniffer-audit.md`. Full bibliography: `references.bib`, `references.md`.
[^ndss]: Meli, McNiece, Reaves. *How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories.* NDSS 2019. doi:10.14722/ndss.2019.23418.
