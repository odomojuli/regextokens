#!/usr/bin/env python3
"""
Generator for the regextokens reference.

Single source of truth -> emits:
  - patterns.json   (machine-readable catalog)
  - readme.md       (brutalist reference, generated from the catalog)

Run:  python3 build_patterns.py
It validates every pattern against its samples before writing anything.

Sample tokens are SYNTHETIC. They satisfy each pattern's shape but contain
only filler characters (mostly repeated 'A'/'a'/'1'). They are not real
credentials.
"""
import json
import re
import sys
import datetime

# strategy legend (stored per entry, surfaced in README):
#   prefix     - distinctive fixed prefix; regex is reliable on its own
#   structure  - fixed structural shape (e.g. UUID, dotted segments)
#   keyword    - low entropy / no prefix; must be gated by a nearby keyword
#   identifier - public handle, not a secret (kept for completeness)
#   encoding   - format validator, not a secret

DATA = [
    # ---- Generic / cryptographic --------------------------------------
    {
        "id": "base64-string",
        "provider": "Generic",
        "category": "Generic / Crypto",
        "name": "Base64 string",
        "regex": r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
        "strategy": "encoding",
        "examples": ["TWFu", "QQ==", "QUI=", "U29tZSB0ZXh0"],
        "non_examples": ["abc", "????", "TWF"],
        "refs": ["https://datatracker.ietf.org/doc/html/rfc4648#section-4"],
        "notes": "Format validator, not a secret. Standard Base64 alphabet with padding. Anchored.",
    },
    {
        "id": "jwt",
        "provider": "Generic",
        "category": "Generic / Crypto",
        "name": "JSON Web Token (JWT)",
        "regex": r"\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9/_-]{10,}\.[A-Za-z0-9/_-]{10,}",
        "strategy": "structure",
        "examples": [
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
        ],
        "non_examples": ["eyJ.ab.cd", "header.payload.sig"],
        "refs": ["https://datatracker.ietf.org/doc/html/rfc7519"],
        "notes": "Three base64url segments. Header begins ey (i.e. {\"). Decode to inspect; signature alone is not the secret.",
    },
    {
        "id": "private-key-block",
        "provider": "Generic",
        "category": "Generic / Crypto",
        "name": "PEM private key block",
        "regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
        "strategy": "prefix",
        "examples": [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        ],
        "non_examples": ["-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----"],
        "refs": ["https://datatracker.ietf.org/doc/html/rfc7468"],
        "notes": "Highest-value single indicator. Matches the header line of any PEM-encoded private key.",
    },

    # ---- Amazon Web Services -----------------------------------------
    {
        "id": "aws-access-key-id",
        "provider": "Amazon Web Services",
        "category": "Cloud",
        "name": "Access key ID",
        "regex": r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b",
        "strategy": "prefix",
        "examples": ["AKIA" + "A" * 16, "ASIA" + "A" * 16, "A3TA" + "A" * 16],
        "non_examples": ["AKIA" + "A" * 10, "AKIA" + "1" * 16, "BKIA" + "A" * 16],
        "refs": [
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html",
            "https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html",
        ],
        "notes": "20 chars. AKIA = long-term IAM key. ASIA = temporary STS/session key. Body is base32 (A-Z, 2-7).",
    },
    {
        "id": "aws-secret-access-key",
        "provider": "Amazon Web Services",
        "category": "Cloud",
        "name": "Secret access key (keyword-gated)",
        "regex": r"(?i)aws[\w.\-= :'\"]{0,25}([A-Za-z0-9/+]{40})",
        "strategy": "keyword",
        "examples": ['aws_secret_access_key = "' + "A" * 40 + '"'],
        "non_examples": ['aws_secret = "' + "A" * 30 + '"'],
        "refs": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html"],
        "notes": "40-char base64 body has no fixed prefix and is low entropy. Gate on an 'aws' keyword or it matches almost any 40-char token.",
    },

    # ---- Google / GCP -------------------------------------------------
    {
        "id": "google-api-key",
        "provider": "Google",
        "category": "Cloud",
        "name": "API key",
        "regex": r"\bAIza[0-9A-Za-z_-]{35}\b",
        "strategy": "prefix",
        "examples": ["AIza" + "A" * 35],
        "non_examples": ["AIza" + "A" * 20, "BIza" + "A" * 35],
        "refs": ["https://cloud.google.com/docs/authentication/api-keys"],
        "notes": "39 chars total. Covers Maps, Firebase, and most GCP API keys.",
    },
    {
        "id": "google-oauth-client-id",
        "provider": "Google",
        "category": "Cloud",
        "name": "OAuth 2.0 client ID",
        "regex": r"\b[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com\b",
        "strategy": "prefix",
        "examples": ["123456789012-" + "a" * 32 + ".apps.googleusercontent.com"],
        "non_examples": ["123-" + "a" * 10 + ".apps.googleusercontent.com"],
        "refs": ["https://developers.google.com/identity/protocols/oauth2"],
        "notes": "Client ID is public, but pins config to a project. Ends in .apps.googleusercontent.com.",
    },
    {
        "id": "google-oauth-client-secret",
        "provider": "Google",
        "category": "Cloud",
        "name": "OAuth 2.0 client secret",
        "regex": r"\bGOCSPX-[0-9A-Za-z_-]{28}\b",
        "strategy": "prefix",
        "examples": ["GOCSPX-" + "A" * 28],
        "non_examples": ["GOCSPX-" + "A" * 10, "GOCSP-" + "A" * 28],
        "refs": ["https://developers.google.com/identity/protocols/oauth2"],
        "notes": "Current client-secret format. Replaced the old unprefixed 24-char secret.",
    },
    {
        "id": "google-oauth-access-token",
        "provider": "Google",
        "category": "Cloud",
        "name": "OAuth 2.0 access token",
        "regex": r"\bya29\.[0-9A-Za-z_-]+",
        "strategy": "prefix",
        "examples": ["ya29." + "A" * 60],
        "non_examples": ["ya30." + "A" * 60, "ya29."],
        "refs": ["https://developers.google.com/identity/protocols/oauth2"],
        "notes": "Short-lived. Prefix ya29. then variable-length body.",
    },
    {
        "id": "google-oauth-refresh-token",
        "provider": "Google",
        "category": "Cloud",
        "name": "OAuth 2.0 refresh token",
        "regex": r"\b1//[0-9A-Za-z_-]{43,128}\b",
        "strategy": "prefix",
        "examples": ["1//0" + "A" * 50],
        "non_examples": ["1//" + "A" * 5, "2//" + "A" * 50],
        "refs": ["https://developers.google.com/identity/protocols/oauth2"],
        "notes": "Begins 1// (note double slash). Replaces the older single-slash 1/ format.",
    },

    # ---- GitHub -------------------------------------------------------
    {
        "id": "github-pat-classic",
        "provider": "GitHub",
        "category": "Source / CI",
        "name": "Personal access token (classic)",
        "regex": r"\bghp_[0-9A-Za-z]{36}\b",
        "strategy": "prefix",
        "examples": ["ghp_" + "A" * 36],
        "non_examples": ["ghp_" + "A" * 20, "ghx_" + "A" * 36],
        "refs": ["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"],
        "notes": "All GitHub v2 tokens carry a checksum in the body; shape match is necessary, not sufficient.",
    },
    {
        "id": "github-pat-fine-grained",
        "provider": "GitHub",
        "category": "Source / CI",
        "name": "Personal access token (fine-grained)",
        "regex": r"\bgithub_pat_[0-9A-Za-z_]{82}\b",
        "strategy": "prefix",
        "examples": ["github_pat_" + "1" * 22 + "_" + "A" * 59],
        "non_examples": ["github_pat_" + "A" * 20],
        "refs": ["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token"],
        "notes": "82 chars after the prefix (22 + '_' + 59).",
    },
    {
        "id": "github-oauth-token",
        "provider": "GitHub",
        "category": "Source / CI",
        "name": "OAuth access token",
        "regex": r"\bgho_[0-9A-Za-z]{36}\b",
        "strategy": "prefix",
        "examples": ["gho_" + "A" * 36],
        "non_examples": ["gho_" + "A" * 35],
        "refs": ["https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps"],
        "notes": "",
    },
    {
        "id": "github-user-to-server",
        "provider": "GitHub",
        "category": "Source / CI",
        "name": "User-to-server token",
        "regex": r"\bghu_[0-9A-Za-z]{36}\b",
        "strategy": "prefix",
        "examples": ["ghu_" + "A" * 36],
        "non_examples": ["ghu_" + "A" * 35],
        "refs": ["https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-with-a-github-app-on-behalf-of-a-user"],
        "notes": "",
    },
    {
        "id": "github-server-to-server",
        "provider": "GitHub",
        "category": "Source / CI",
        "name": "Server-to-server token",
        "regex": r"\bghs_[0-9A-Za-z]{36}\b",
        "strategy": "prefix",
        "examples": ["ghs_" + "A" * 36],
        "non_examples": ["ghs_" + "A" * 35],
        "refs": ["https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/about-authentication-with-a-github-app"],
        "notes": "",
    },
    {
        "id": "github-refresh-token",
        "provider": "GitHub",
        "category": "Source / CI",
        "name": "Refresh token",
        "regex": r"\bghr_[0-9A-Za-z]{36}\b",
        "strategy": "prefix",
        "examples": ["ghr_" + "A" * 36],
        "non_examples": ["ghr_" + "A" * 35],
        "refs": ["https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens"],
        "notes": "",
    },

    # ---- GitLab -------------------------------------------------------
    {
        "id": "gitlab-pat",
        "provider": "GitLab",
        "category": "Source / CI",
        "name": "Personal access token",
        "regex": r"\bglpat-[0-9A-Za-z_-]{20}\b",
        "strategy": "prefix",
        "examples": ["glpat-" + "A" * 20],
        "non_examples": ["glpat-" + "A" * 10, "glpat" + "A" * 20],
        "refs": ["https://docs.gitlab.com/ee/security/token_overview.html"],
        "notes": "GitLab moved all tokens to typed gl* prefixes.",
    },
    {
        "id": "gitlab-oauth-app-secret",
        "provider": "GitLab",
        "category": "Source / CI",
        "name": "OAuth application secret",
        "regex": r"\bgloas-[0-9A-Za-z_-]{64}\b",
        "strategy": "prefix",
        "examples": ["gloas-" + "A" * 64],
        "non_examples": ["gloas-" + "A" * 20],
        "refs": ["https://docs.gitlab.com/ee/security/token_overview.html"],
        "notes": "",
    },
    {
        "id": "gitlab-pipeline-trigger-token",
        "provider": "GitLab",
        "category": "Source / CI",
        "name": "Pipeline trigger token",
        "regex": r"\bglptt-[0-9a-f]{40}\b",
        "strategy": "prefix",
        "examples": ["glptt-" + "a" * 40],
        "non_examples": ["glptt-" + "a" * 20],
        "refs": ["https://docs.gitlab.com/ee/security/token_overview.html"],
        "notes": "",
    },
    {
        "id": "gitlab-runner-token",
        "provider": "GitLab",
        "category": "Source / CI",
        "name": "Runner authentication token",
        "regex": r"\bglrt-[0-9A-Za-z_-]{20}\b",
        "strategy": "prefix",
        "examples": ["glrt-" + "A" * 20],
        "non_examples": ["glrt-" + "A" * 10],
        "refs": ["https://docs.gitlab.com/ee/security/token_overview.html"],
        "notes": "",
    },

    # ---- OpenAI / Anthropic / HF -------------------------------------
    {
        "id": "openai-api-key",
        "provider": "OpenAI",
        "category": "AI",
        "name": "API key",
        "regex": r"\bsk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{20,74}T3BlbkFJ[0-9A-Za-z_-]{20,74}\b",
        "strategy": "prefix",
        "examples": [
            "sk-proj-" + "A" * 30 + "T3BlbkFJ" + "A" * 30,
            "sk-svcacct-" + "A" * 25 + "T3BlbkFJ" + "A" * 25,
            "sk-" + "A" * 30 + "T3BlbkFJ" + "A" * 30,
        ],
        "non_examples": ["sk-proj-" + "A" * 10, "sk-" + "A" * 48],
        "refs": ["https://platform.openai.com/docs/api-reference/authentication"],
        "notes": "Modern keys embed the literal T3BlbkFJ (base64 'OpenAI') mid-token. Optional sub-prefixes proj-/svcacct-/admin-.",
    },
    {
        "id": "openai-api-key-legacy",
        "provider": "OpenAI",
        "category": "AI",
        "name": "API key (legacy, no longer issued)",
        "regex": r"\bsk-[0-9A-Za-z]{48}\b",
        "strategy": "prefix",
        "examples": ["sk-" + "A" * 48],
        "non_examples": ["sk-" + "A" * 20],
        "refs": ["https://platform.openai.com/docs/api-reference/authentication"],
        "notes": "Pre-2024 format. High false-positive rate (any sk- + 48 alnum). Prefer the T3BlbkFJ-anchored rule above.",
    },
    {
        "id": "anthropic-api-key",
        "provider": "Anthropic",
        "category": "AI",
        "name": "API key",
        "regex": r"\bsk-ant-api03-[0-9A-Za-z_-]{93}AA\b",
        "strategy": "prefix",
        "examples": ["sk-ant-api03-" + "A" * 93 + "AA"],
        "non_examples": ["sk-ant-api03-" + "A" * 20, "sk-ant-" + "A" * 93 + "AA"],
        "refs": ["https://docs.anthropic.com/en/api/getting-started"],
        "notes": "Body is fixed length and ends in AA.",
    },
    {
        "id": "anthropic-admin-key",
        "provider": "Anthropic",
        "category": "AI",
        "name": "Admin API key",
        "regex": r"\bsk-ant-admin01-[0-9A-Za-z_-]{93}AA\b",
        "strategy": "prefix",
        "examples": ["sk-ant-admin01-" + "A" * 93 + "AA"],
        "non_examples": ["sk-ant-admin01-" + "A" * 20],
        "refs": ["https://docs.anthropic.com/en/api/administration"],
        "notes": "",
    },
    {
        "id": "huggingface-token",
        "provider": "Hugging Face",
        "category": "AI",
        "name": "User access token",
        "regex": r"\bhf_[0-9A-Za-z]{34}\b",
        "strategy": "prefix",
        "examples": ["hf_" + "A" * 34],
        "non_examples": ["hf_" + "A" * 20],
        "refs": ["https://huggingface.co/docs/hub/security-tokens"],
        "notes": "",
    },

    # ---- Package registries ------------------------------------------
    {
        "id": "npm-token",
        "provider": "npm",
        "category": "Source / CI",
        "name": "Access token",
        "regex": r"\bnpm_[0-9A-Za-z]{36}\b",
        "strategy": "prefix",
        "examples": ["npm_" + "A" * 36],
        "non_examples": ["npm_" + "A" * 20],
        "refs": ["https://docs.npmjs.com/about-access-tokens"],
        "notes": "Prefix introduced 2021; final chars encode a CRC32 checksum.",
    },
    {
        "id": "pypi-token",
        "provider": "PyPI",
        "category": "Source / CI",
        "name": "Upload token",
        "regex": r"\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,1000}\b",
        "strategy": "prefix",
        "examples": ["pypi-AgEIcHlwaS5vcmc" + "A" * 70],
        "non_examples": ["pypi-" + "A" * 70, "pypi-AgEIcHlwaS5vcmc" + "A" * 10],
        "refs": ["https://pypi.org/help/#apitoken"],
        "notes": "Macaroon. The static segment AgEIcHlwaS5vcmc is base64 'pypi.org'.",
    },

    # ---- Payments -----------------------------------------------------
    {
        "id": "stripe-secret-key",
        "provider": "Stripe",
        "category": "Payments",
        "name": "Secret / restricted key",
        "regex": r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99}\b",
        "strategy": "prefix",
        "examples": ["sk_live_" + "A" * 24, "rk_live_" + "A" * 40, "sk_test_" + "A" * 24],
        "non_examples": ["sk_live_" + "A" * 10, "pk_live_" + "A" * 24],
        "refs": ["https://docs.stripe.com/keys"],
        "notes": "sk_ = full secret, rk_ = restricted (scoped). live/test mode. Length now variable (legacy 24, newer keys far longer).",
    },
    {
        "id": "stripe-publishable-key",
        "provider": "Stripe",
        "category": "Payments",
        "name": "Publishable key",
        "regex": r"\bpk_(?:live|test)_[0-9A-Za-z]{24,99}\b",
        "strategy": "prefix",
        "examples": ["pk_live_" + "A" * 24],
        "non_examples": ["pk_live_" + "A" * 10],
        "refs": ["https://docs.stripe.com/keys"],
        "notes": "Client-side, not secret, but useful for environment fingerprinting.",
    },
    {
        "id": "square-access-token",
        "provider": "Square",
        "category": "Payments",
        "name": "Production access token",
        "regex": r"\bEAAA[0-9A-Za-z_-]{60}\b",
        "strategy": "prefix",
        "examples": ["EAAA" + "A" * 60],
        "non_examples": ["EAAA" + "A" * 20],
        "refs": ["https://developer.squareup.com/docs/build-basics/access-tokens"],
        "notes": "Current OAuth/personal access token format.",
    },
    {
        "id": "square-access-token-legacy",
        "provider": "Square",
        "category": "Payments",
        "name": "Access token (legacy)",
        "regex": r"\bsq0atp-[0-9A-Za-z_-]{22}\b",
        "strategy": "prefix",
        "examples": ["sq0atp-" + "A" * 22],
        "non_examples": ["sq0atp-" + "A" * 10, "sqOatp-" + "A" * 22],
        "refs": ["https://developer.squareup.com/docs/build-basics/access-tokens"],
        "notes": "Prefix is sq-zero-atp. The capital-O 'sqOatp' in older lists is wrong.",
    },
    {
        "id": "square-oauth-secret-legacy",
        "provider": "Square",
        "category": "Payments",
        "name": "OAuth secret (legacy)",
        "regex": r"\bsq0csp-[0-9A-Za-z_-]{43}\b",
        "strategy": "prefix",
        "examples": ["sq0csp-" + "A" * 43],
        "non_examples": ["sq0csp-" + "A" * 10, "q0csp-" + "A" * 43],
        "refs": ["https://developer.squareup.com/docs/build-basics/access-tokens"],
        "notes": "Prefix is sq-zero-csp.",
    },
    {
        "id": "paypal-braintree-access-token",
        "provider": "PayPal / Braintree",
        "category": "Payments",
        "name": "Access token",
        "regex": r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b",
        "strategy": "structure",
        "examples": ["access_token$production$" + "a" * 16 + "$" + "a" * 32],
        "non_examples": ["access_token$sandbox$" + "a" * 16 + "$" + "a" * 32],
        "refs": ["https://developer.paypal.com/braintree/docs/guides/authorization/gateway-credentials"],
        "notes": "Dollar-delimited: access_token$production$<16>$<32>. The mangled entry in older lists never compiled.",
    },
    {
        "id": "picatic-api-key",
        "provider": "Picatic",
        "category": "Payments",
        "name": "API key (DEPRECATED service)",
        "regex": r"\bsk_live_[0-9a-z]{32}\b",
        "strategy": "prefix",
        "examples": ["sk_live_" + "a" * 32],
        "non_examples": ["sk_live_" + "a" * 10],
        "refs": ["https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf"],
        "notes": "Picatic shut down in 2018. Kept for historical scanning only. Note the prefix collides with Stripe-style sk_live_.",
    },

    # ---- Shopify ------------------------------------------------------
    {
        "id": "shopify-access-token",
        "provider": "Shopify",
        "category": "Payments",
        "name": "Admin API access token",
        "regex": r"\bshpat_[0-9a-fA-F]{32}\b",
        "strategy": "prefix",
        "examples": ["shpat_" + "a" * 32],
        "non_examples": ["shpat_" + "a" * 10],
        "refs": ["https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens"],
        "notes": "shpat_ = admin API. Related prefixes: shpss_ (shared secret), shppa_ (private app), shpca_ (custom app).",
    },
    {
        "id": "shopify-shared-secret",
        "provider": "Shopify",
        "category": "Payments",
        "name": "Shared secret",
        "regex": r"\bshpss_[0-9a-fA-F]{32}\b",
        "strategy": "prefix",
        "examples": ["shpss_" + "a" * 32],
        "non_examples": ["shpss_" + "a" * 10],
        "refs": ["https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens"],
        "notes": "",
    },
    {
        "id": "shopify-private-app-token",
        "provider": "Shopify",
        "category": "Payments",
        "name": "Private app access token",
        "regex": r"\bshppa_[0-9a-fA-F]{32}\b",
        "strategy": "prefix",
        "examples": ["shppa_" + "a" * 32],
        "non_examples": ["shppa_" + "a" * 10],
        "refs": ["https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens"],
        "notes": "",
    },
    {
        "id": "shopify-custom-app-token",
        "provider": "Shopify",
        "category": "Payments",
        "name": "Custom app access token",
        "regex": r"\bshpca_[0-9a-fA-F]{32}\b",
        "strategy": "prefix",
        "examples": ["shpca_" + "a" * 32],
        "non_examples": ["shpca_" + "a" * 10],
        "refs": ["https://shopify.dev/docs/apps/build/authentication-authorization/access-tokens"],
        "notes": "",
    },

    # ---- Communications / email --------------------------------------
    {
        "id": "slack-bot-token",
        "provider": "Slack",
        "category": "Comms",
        "name": "Bot token (xoxb)",
        "regex": r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9A-Za-z]{24,34}\b",
        "strategy": "prefix",
        "examples": ["xoxb-" + "1" * 11 + "-" + "1" * 11 + "-" + "A" * 24],
        "non_examples": ["xoxb-" + "1" * 5 + "-" + "1" * 5 + "-" + "A" * 24],
        "refs": ["https://api.slack.com/authentication/token-types"],
        "notes": "Segment lengths are now variable; fixed {11}-{11}-{24} from older lists misses current tokens.",
    },
    {
        "id": "slack-user-token",
        "provider": "Slack",
        "category": "Comms",
        "name": "User token (xoxp)",
        "regex": r"\bxoxp-(?:[0-9]{10,13}-){3}[0-9A-Za-z]{28,34}\b",
        "strategy": "prefix",
        "examples": ["xoxp-" + "1" * 11 + "-" + "1" * 11 + "-" + "1" * 11 + "-" + "A" * 28],
        "non_examples": ["xoxp-" + "1" * 11 + "-" + "A" * 28],
        "refs": ["https://api.slack.com/authentication/token-types"],
        "notes": "",
    },
    {
        "id": "slack-config-token",
        "provider": "Slack",
        "category": "Comms",
        "name": "App configuration token (xoxe.xoxp)",
        "regex": r"\bxoxe\.xox[bp]-\d-[0-9A-Za-z]{146,166}\b",
        "strategy": "prefix",
        "examples": ["xoxe.xoxp-1-" + "A" * 160],
        "non_examples": ["xoxe.xoxp-1-" + "A" * 20],
        "refs": ["https://api.slack.com/authentication/rotation"],
        "notes": "",
    },
    {
        "id": "slack-refresh-token",
        "provider": "Slack",
        "category": "Comms",
        "name": "Refresh token (xoxe)",
        "regex": r"\bxoxe-\d-[0-9A-Za-z]{146,166}\b",
        "strategy": "prefix",
        "examples": ["xoxe-1-" + "A" * 147],
        "non_examples": ["xoxe-1-" + "A" * 20],
        "refs": ["https://api.slack.com/authentication/rotation"],
        "notes": "",
    },
    {
        "id": "slack-webhook-url",
        "provider": "Slack",
        "category": "Comms",
        "name": "Incoming webhook URL",
        "regex": r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,12}/B[0-9A-Za-z_]{8,12}/[0-9A-Za-z]{24}",
        "strategy": "prefix",
        "examples": ["https://hooks.slack.com/services/T" + "A" * 10 + "/B" + "A" * 10 + "/" + "A" * 24],
        "non_examples": ["https://hooks.slack.com/services/T" + "A" * 10 + "/B" + "A" * 10],
        "refs": ["https://api.slack.com/messaging/webhooks"],
        "notes": "Full URL is the secret. Old bare T../B../.. shape produced false positives.",
    },
    {
        "id": "twilio-account-sid",
        "provider": "Twilio",
        "category": "Comms",
        "name": "Account SID",
        "regex": r"\bAC[0-9a-fA-F]{32}\b",
        "strategy": "prefix",
        "examples": ["AC" + "a" * 32],
        "non_examples": ["AC" + "a" * 10, "55" + "a" * 32],
        "refs": ["https://www.twilio.com/docs/iam/api-keys"],
        "notes": "Prefix AC + 32 hex. Older '55...' lists were incorrect.",
    },
    {
        "id": "twilio-api-key-sid",
        "provider": "Twilio",
        "category": "Comms",
        "name": "API key SID",
        "regex": r"\bSK[0-9a-fA-F]{32}\b",
        "strategy": "prefix",
        "examples": ["SK" + "a" * 32],
        "non_examples": ["SK" + "a" * 10],
        "refs": ["https://www.twilio.com/docs/iam/api-keys"],
        "notes": "Pairs with a 32-hex secret (no prefix; gate on a 'twilio' keyword).",
    },
    {
        "id": "sendgrid-api-key",
        "provider": "SendGrid",
        "category": "Comms",
        "name": "API key",
        "regex": r"\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b",
        "strategy": "prefix",
        "examples": ["SG." + "A" * 22 + "." + "A" * 43],
        "non_examples": ["SG." + "A" * 10 + "." + "A" * 20],
        "refs": ["https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys"],
        "notes": "SG.<22>.<43>",
    },
    {
        "id": "mailgun-private-key",
        "provider": "Mailgun",
        "category": "Comms",
        "name": "Private API key",
        "regex": r"\bkey-[0-9a-f]{32}\b",
        "strategy": "prefix",
        "examples": ["key-" + "a" * 32],
        "non_examples": ["key-" + "a" * 10],
        "refs": ["https://documentation.mailgun.com/docs/mailgun/api-reference/authentication/"],
        "notes": "",
    },
    {
        "id": "mailchimp-api-key",
        "provider": "Mailchimp",
        "category": "Comms",
        "name": "API key",
        "regex": r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
        "strategy": "structure",
        "examples": ["a" * 32 + "-us1", "a" * 32 + "-us21"],
        "non_examples": ["a" * 10 + "-us1", "a" * 32 + "-eu1"],
        "refs": ["https://mailchimp.com/developer/marketing/guides/quick-start/"],
        "notes": "Trailing -us<dc> is the datacenter. The 32-hex prefix alone is not distinctive.",
    },
    {
        "id": "discord-bot-token",
        "provider": "Discord",
        "category": "Comms",
        "name": "Bot token",
        "regex": r"\b[MNO][0-9A-Za-z_-]{23,25}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27,38}\b",
        "strategy": "structure",
        "examples": ["M" + "A" * 23 + "." + "A" * 6 + "." + "A" * 30],
        "non_examples": ["M" + "A" * 23 + "." + "A" * 6],
        "refs": ["https://discord.com/developers/docs/topics/oauth2"],
        "notes": "Three dot-separated base64url segments; first encodes the bot user ID. Approximate; verify by decoding segment 1.",
    },

    # ---- Social -------------------------------------------------------
    {
        "id": "twitter-bearer-token",
        "provider": "Twitter / X",
        "category": "Social",
        "name": "App-only bearer token",
        "regex": r"\bA{22}[0-9A-Za-z%]{80,}",
        "strategy": "prefix",
        "examples": ["A" * 22 + "B" * 90],
        "non_examples": ["A" * 22 + "B" * 10],
        "refs": ["https://developer.twitter.com/en/docs/authentication/oauth-2-0/bearer-tokens"],
        "notes": "Begins with a long run of 'A' (base64 padding), then URL-encoded body.",
    },
    {
        "id": "twitter-access-token-legacy",
        "provider": "Twitter / X",
        "category": "Social",
        "name": "OAuth 1.0a access token",
        "regex": r"\b[1-9][0-9]+-[0-9A-Za-z]{40}\b",
        "strategy": "structure",
        "examples": ["12345678-" + "A" * 40],
        "non_examples": ["12345678-" + "A" * 10],
        "refs": ["https://developer.twitter.com/en/docs/authentication/oauth-1-0a"],
        "notes": "<numeric user id>-<40 alnum>. Structural; pair with a 'twitter' keyword to cut noise.",
    },
    {
        "id": "twitter-username",
        "provider": "Twitter / X",
        "category": "Social",
        "name": "Username / handle",
        "regex": r"(?:^|[^@\w])@(\w{1,15})\b",
        "strategy": "identifier",
        "examples": ["@jack", "hello @user1"],
        "non_examples": ["email@host", "@"],
        "refs": ["https://github.com/twitter/twitter-text/blob/master/rb/lib/twitter-text/regex.rb"],
        "notes": "Public handle, not a secret. 1-15 word chars, not preceded by @ or word char.",
    },
    {
        "id": "facebook-access-token",
        "provider": "Facebook",
        "category": "Social",
        "name": "Access token",
        "regex": r"\bEAA[0-9A-Za-z]{90,}\b",
        "strategy": "prefix",
        "examples": ["EAA" + "A" * 120],
        "non_examples": ["EAA" + "A" * 20],
        "refs": ["https://developers.facebook.com/docs/facebook-login/guides/access-tokens"],
        "notes": "Graph API tokens begin EAA. The old fixed 'EAACEdEose0cBA' app prefix is obsolete.",
    },
    {
        "id": "instagram-access-token",
        "provider": "Instagram",
        "category": "Social",
        "name": "Access token",
        "regex": r"\bIGQ[0-9A-Za-z_-]{100,}",
        "strategy": "prefix",
        "examples": ["IGQ" + "A" * 150],
        "non_examples": ["IGQ" + "A" * 20],
        "refs": ["https://developers.facebook.com/docs/instagram-platform"],
        "notes": "Instagram Basic Display was deprecated Dec 2024; current long-lived tokens (IGQ / Facebook EAA) are issued via the Instagram API with Facebook Login.",
    },
    {
        "id": "instagram-username",
        "provider": "Instagram",
        "category": "Social",
        "name": "Username",
        "regex": r"(?:^|[^\w])@([A-Za-z0-9_.]{1,30})\b",
        "strategy": "identifier",
        "examples": ["@some.user", "hi @user_1"],
        "non_examples": ["@", "foo"],
        "refs": ["https://blog.jstassen.com/2016/03/code-regex-for-instagram-username-and-hashtags/"],
        "notes": "Public handle. RE2-safe rewrite of the old lookahead-based pattern.",
    },
    {
        "id": "foursquare-service-key",
        "provider": "Foursquare",
        "category": "Social",
        "name": "Service API key",
        "regex": r"\bfsq3[0-9A-Za-z/+_-]{40,}={0,2}",
        "strategy": "prefix",
        "examples": ["fsq3" + "A" * 44],
        "non_examples": ["fsq3" + "A" * 10, "fsq2" + "A" * 44],
        "refs": ["https://docs.foursquare.com/developer/reference/personalization-apis-authentication"],
        "notes": "Current Places API key prefix fsq3. The old '[0-9a-zA-Z_]{5,31}' client key was too generic to detect; the original list also mis-typed it as a character class.",
    },

    # ---- Productivity / data -----------------------------------------
    {
        "id": "linear-api-key",
        "provider": "Linear",
        "category": "Productivity",
        "name": "API key",
        "regex": r"\blin_api_[0-9A-Za-z]{40}\b",
        "strategy": "prefix",
        "examples": ["lin_api_" + "A" * 40],
        "non_examples": ["lin_api_" + "A" * 10],
        "refs": ["https://developers.linear.app/docs/graphql/working-with-the-graphql-api"],
        "notes": "",
    },
    {
        "id": "databricks-token",
        "provider": "Databricks",
        "category": "Productivity",
        "name": "Personal access token",
        "regex": r"\bdapi[0-9a-f]{32}(?:-\d)?\b",
        "strategy": "prefix",
        "examples": ["dapi" + "a" * 32, "dapi" + "a" * 32 + "-2"],
        "non_examples": ["dapi" + "a" * 10],
        "refs": ["https://docs.databricks.com/en/dev-tools/auth/pat.html"],
        "notes": "",
    },
    {
        "id": "doppler-token",
        "provider": "Doppler",
        "category": "Productivity",
        "name": "Personal token",
        "regex": r"\bdp\.pt\.[0-9A-Za-z]{43}\b",
        "strategy": "prefix",
        "examples": ["dp.pt." + "A" * 43],
        "non_examples": ["dp.pt." + "A" * 10],
        "refs": ["https://docs.doppler.com/docs/service-tokens"],
        "notes": "Other Doppler scopes use dp.st. (service), dp.sa. (service account).",
    },
    {
        "id": "digitalocean-pat",
        "provider": "DigitalOcean",
        "category": "Cloud",
        "name": "Personal access token",
        "regex": r"\bdop_v1_[0-9a-f]{64}\b",
        "strategy": "prefix",
        "examples": ["dop_v1_" + "a" * 64],
        "non_examples": ["dop_v1_" + "a" * 20],
        "refs": ["https://docs.digitalocean.com/reference/api/create-personal-access-token/"],
        "notes": "OAuth token dor_v1_ / refresh dor_v1_ share the same shape.",
    },
    {
        "id": "heroku-api-key",
        "provider": "Heroku",
        "category": "Cloud",
        "name": "API key (keyword-gated UUID)",
        "regex": r"(?i)heroku[\w.\-= :'\"]{0,25}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        "strategy": "keyword",
        "examples": ["heroku_api_key=" + "a" * 8 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 12],
        "non_examples": [("a" * 8 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 12)],
        "refs": ["https://devcenter.heroku.com/articles/platform-api-quickstart"],
        "notes": "Legacy keys are bare UUIDs - indistinguishable from any UUID without a 'heroku' keyword. Newer keys use the HRKU- prefix.",
    },
    {
        "id": "heroku-api-key-v2",
        "provider": "Heroku",
        "category": "Cloud",
        "name": "API key (v2)",
        "regex": r"\bHRKU-[0-9A-Za-z_-]{58,}\b",
        "strategy": "prefix",
        "examples": ["HRKU-AA" + "A" * 58],
        "non_examples": ["HRKU-" + "A" * 10],
        "refs": ["https://devcenter.heroku.com/articles/platform-api-quickstart"],
        "notes": "",
    },

    # ---- Amazon MWS ---------------------------------------------------
    {
        "id": "amazon-mws-auth-token",
        "provider": "Amazon MWS",
        "category": "Cloud",
        "name": "Auth token (DEPRECATED API)",
        "regex": r"\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "strategy": "structure",
        "examples": ["amzn.mws." + "a" * 8 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 12],
        "non_examples": ["amzn.mws." + "a" * 8],
        "refs": ["https://developer-docs.amazon.com/sp-api/docs/migrating-from-amazon-mws"],
        "notes": "amzn.mws.<UUID>. MWS retired in favor of SP-API (Login with Amazon tokens, prefixes Atza|/Atzr|). Original list entry was malformed.",
    },

    # ---- Folded in from upstream readme.md (origin/master) ------------
    {
        "id": "cloudflare-api-token",
        "provider": "Cloudflare",
        "category": "Cloud",
        "name": "API token (keyword-gated)",
        "regex": r"(?i)cloudflare[\w.\-= :'\"]{0,25}([A-Za-z0-9_-]{40})",
        "strategy": "keyword",
        "examples": ['cloudflare_api_token = "' + "A" * 40 + '"'],
        "non_examples": ['cloudflare_api_token = "' + "A" * 20 + '"'],
        "refs": ["https://developers.cloudflare.com/fundamentals/api/get-started/create-token/"],
        "notes": "40-char token, no fixed prefix; gate on a 'cloudflare' keyword or it matches any 40-char string.",
    },
    {
        "id": "cloudflare-global-api-key",
        "provider": "Cloudflare",
        "category": "Cloud",
        "name": "Global API key (legacy, keyword-gated)",
        "regex": r"(?i)cloudflare[\w.\-= :'\"]{0,25}([a-f0-9]{37})",
        "strategy": "keyword",
        "examples": ["cloudflare_global_api_key=" + "a" * 37],
        "non_examples": ["cloudflare_global_api_key=" + "a" * 20],
        "refs": ["https://developers.cloudflare.com/fundamentals/api/get-started/keys/"],
        "notes": "Legacy 37-hex global key; keyword-gated. Prefer scoped API tokens.",
    },
    {
        "id": "cloudflare-origin-ca-key",
        "provider": "Cloudflare",
        "category": "Cloud",
        "name": "Origin CA key",
        "regex": r"\bv1\.0-[0-9a-f]{24}-[0-9a-f]{146}\b",
        "strategy": "prefix",
        "examples": ["v1.0-" + "a" * 24 + "-" + "a" * 146],
        "non_examples": ["v1.0-" + "a" * 24],
        "refs": ["https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/"],
        "notes": "Distinctive v1.0- prefix; regex-reliable.",
    },
    {
        "id": "vercel-access-token",
        "provider": "Vercel",
        "category": "Cloud",
        "name": "Access token (2024+ format)",
        "regex": r"\bvcp_[A-Za-z0-9]{24}\b",
        "strategy": "prefix",
        "examples": ["vcp_" + "A" * 24],
        "non_examples": ["vcp_" + "A" * 10],
        "refs": ["https://vercel.com/changelog/new-token-formats-and-secret-scanning"],
        "notes": "Prefixed format introduced 2024. Related: vck_ (AI Gateway), cl_ (OAuth client id).",
    },
    {
        "id": "datadog-api-key",
        "provider": "Datadog",
        "category": "Productivity",
        "name": "API key (keyword-gated)",
        "regex": r"(?i)datadog[\w.\-= :'\"]{0,25}([a-f0-9]{32})",
        "strategy": "keyword",
        "examples": ["datadog_api_key=" + "a" * 32],
        "non_examples": ["datadog_api_key=" + "a" * 16],
        "refs": ["https://docs.datadoghq.com/account_management/api-app-keys/"],
        "notes": "32-hex key, no prefix; gate on a 'datadog' keyword. Often paired with a 40-hex application key.",
    },
    {
        "id": "datadog-application-key",
        "provider": "Datadog",
        "category": "Productivity",
        "name": "Application key (keyword-gated)",
        "regex": r"(?i)datadog[\w.\-= :'\"]{0,25}([a-f0-9]{40})",
        "strategy": "keyword",
        "examples": ["datadog_app_key=" + "a" * 40],
        "non_examples": ["datadog_app_key=" + "a" * 20],
        "refs": ["https://docs.datadoghq.com/account_management/api-app-keys/"],
        "notes": "40-hex application key, no prefix; keyword-gated.",
    },
    {
        "id": "wakatime-api-key",
        "provider": "WakaTime",
        "category": "Productivity",
        "name": "API key",
        "regex": r"\bwaka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        "strategy": "prefix",
        "examples": ["waka_" + "a" * 8 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 12],
        "non_examples": ["waka_" + "a" * 8],
        "refs": ["https://wakatime.com/developers"],
        "notes": "waka_ + UUID.",
    },
    {
        "id": "braintree-tokenization-key",
        "provider": "PayPal / Braintree",
        "category": "Payments",
        "name": "Tokenization key (publishable)",
        "regex": r"\b(?:production|sandbox)_[0-9a-z]{8}_[0-9a-z]{16,}\b",
        "strategy": "prefix",
        "examples": ["sandbox_" + "a" * 8 + "_" + "a" * 24, "production_" + "a" * 8 + "_" + "a" * 24],
        "non_examples": ["staging_" + "a" * 8 + "_" + "a" * 24],
        "refs": ["https://developer.paypal.com/braintree/docs/guides/authorization/tokenization-key"],
        "notes": "Environment-prefixed and publishable (client-side, not a secret) - like Stripe pk_.",
    },
]


def validate(entries):
    errors = []
    seen_ids = set()
    for e in entries:
        eid = e["id"]
        if eid in seen_ids:
            errors.append(f"{eid}: duplicate id")
        seen_ids.add(eid)
        try:
            rx = re.compile(e["regex"])
        except re.error as exc:
            errors.append(f"{eid}: does not compile: {exc}")
            continue
        for s in e["examples"]:
            if not rx.search(s):
                errors.append(f"{eid}: positive sample did NOT match: {s!r}")
        for s in e["non_examples"]:
            if rx.search(s):
                errors.append(f"{eid}: negative sample matched (should not): {s!r}")
    return errors


def write_json(entries, path):
    # Strip test samples from the published catalog. An example token that
    # matches one of these patterns also matches the issuer's own secret
    # scanner, so committing the samples trips push protection (GitHub et al.).
    # Samples stay in DATA (above) and are exercised by tests/test_patterns.py.
    public = [
        {k: v for k, v in e.items() if k not in ("examples", "non_examples")}
        for e in entries
    ]
    payload = {
        "name": "regextokens",
        "description": "Modernized regex patterns for OAuth / API token scanning.",
        "generated": datetime.date.today().isoformat(),
        "flavor": "RE2-compatible (Go) and Python re. No lookbehind/backreferences.",
        "count": len(public),
        "strategy_legend": {
            "prefix": "Distinctive fixed prefix; regex reliable on its own.",
            "structure": "Fixed structural shape (UUID, dotted/delimited segments).",
            "keyword": "Low entropy / no prefix; gate on a nearby keyword.",
            "identifier": "Public handle, not a secret.",
            "encoding": "Format validator, not a secret.",
        },
        "fields": {
            "id": "stable slug",
            "provider": "issuing service",
            "category": "grouping",
            "name": "token type",
            "regex": "the pattern (designed for re.search / scanning)",
            "strategy": "see strategy_legend",
            "refs": "source URLs",
            "notes": "caveats",
        },
        "samples_note": "Positive/negative test tokens are defined in build_patterns.py and exercised by tests/test_patterns.py. They are intentionally omitted here: a sample that matches a pattern also matches issuer secret scanners, which would block commits.",
        "patterns": public,
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def write_readme(entries, path):
    by_cat = {}
    for e in entries:
        by_cat.setdefault(e["category"], {}).setdefault(e["provider"], []).append(e)

    cat_order = ["Generic / Crypto", "Cloud", "Source / CI", "AI",
                 "Payments", "Comms", "Social", "Productivity"]
    cats = [c for c in cat_order if c in by_cat] + [c for c in by_cat if c not in cat_order]

    L = []
    L.append("# regextokens")
    L.append("")
    L.append("Regex reference for scanning OAuth / API tokens and secrets. "
             "Each entry: the pattern, a source, and caveats. "
             "Source of truth is `patterns.json`; this file is generated from it.")
    L.append("")
    L.append(f"`{len(entries)}` patterns / `{len(set(e['provider'] for e in entries))}` providers / "
             f"generated `{datetime.date.today().isoformat()}`")
    L.append("")
    L.append("## Use")
    L.append("")
    L.append("```")
    L.append("pip install pytest")
    L.append("pytest                 # validate every pattern against its samples")
    L.append("python build_patterns.py   # regenerate patterns.json + readme.md")
    L.append("```")
    L.append("")
    L.append("Consume the catalog:")
    L.append("")
    L.append("```python")
    L.append("import json, re")
    L.append('pats = json.load(open("patterns.json"))["patterns"]')
    L.append('rx = {p["id"]: re.compile(p["regex"]) for p in pats}')
    L.append('rx["github-pat-classic"].search(text)')
    L.append("```")
    L.append("")
    L.append("## Files")
    L.append("")
    L.append("- `patterns.json` — source of truth (the catalog).")
    L.append("- `build_patterns.py` — generator + validator; rebuilds readme.md and patterns.json.")
    L.append("- `tests/test_patterns.py` — pytest suite: compiles, matches, and RE2-checks every pattern.")
    L.append("- `sniffer-audit.md` — audit of other secret scanners (verification, staleness).")
    L.append("- `references.bib` / `references.md` — bibliography of the secret-detection literature.")
    L.append("")
    L.append("## Conventions")
    L.append("")
    L.append("- Flavor: RE2-compatible (gitleaks/Go) and Python `re`. No lookbehind or backreferences.")
    L.append("- Patterns are written for `re.search` (scanning embedded text). Wrap with `^`/`$` to use as validators.")
    L.append("- `\\b` word boundaries bracket most tokens. Drop them if scanning inside base64 blobs.")
    L.append("- Strategy tag per entry: `prefix` = reliable alone; `structure` = fixed shape; "
             "`keyword` = gate on a nearby keyword; `identifier` = public, not secret; "
             "`encoding` = format check, not secret.")
    L.append("- A shape match is necessary, not sufficient. Many issuers embed checksums; verify before acting.[^verify]")
    L.append("- Example tokens in `patterns.json` are synthetic filler, not live credentials.")
    L.append("")
    L.append("## References")
    L.append("")
    L.append("- `sniffer-audit.md` — how major scanners build and verify patterns, with benchmark data.")
    L.append("- `references.bib` / `references.md` — bibliography of the secret-detection literature.")
    L.append("- Pattern lineage traces to Meli et al., *How Bad Can It Git?* (NDSS 2019).[^ndss]")
    L.append("")
    L.append("## Index")
    L.append("")
    for cat in cats:
        provs = ", ".join(sorted(by_cat[cat]))
        L.append(f"- {cat}: {provs}")
    L.append("")

    for cat in cats:
        L.append(f"## {cat}")
        L.append("")
        for prov in sorted(by_cat[cat]):
            L.append(f"### {prov}")
            L.append("")
            for e in by_cat[cat][prov]:
                L.append(f"**{e['name']}** `[{e['strategy']}]`")
                L.append("")
                L.append("```")
                L.append(e["regex"])
                L.append("```")
                L.append("")
                if e.get("notes"):
                    L.append(e["notes"])
                    L.append("")
                for r in e["refs"]:
                    L.append(f"src: {r}")
                L.append("")
    # footnote definitions (collected and rendered at the bottom by GitHub Markdown)
    L.append("")
    L.append("[^verify]: Shape-matching vs. live verification, and the staleness of copied "
             "regex lists, are examined in `sniffer-audit.md`. Full bibliography: "
             "`references.bib`, `references.md`.")
    L.append("[^ndss]: Meli, McNiece, Reaves. *How Bad Can It Git? Characterizing Secret "
             "Leakage in Public GitHub Repositories.* NDSS 2019. doi:10.14722/ndss.2019.23418.")
    # trim trailing blanks
    while L and L[-1] == "":
        L.pop()
    L.append("")
    with open(path, "w") as f:
        f.write("\n".join(L))


def main():
    errs = validate(DATA)
    if errs:
        print("VALIDATION FAILED:")
        for e in errs:
            print("  -", e)
        sys.exit(1)
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    write_json(DATA, os.path.join(here, "patterns.json"))
    write_readme(DATA, os.path.join(here, "readme.md"))
    print(f"OK: {len(DATA)} patterns validated and written.")
    print(f"    providers: {len(set(e['provider'] for e in DATA))}")
    cats = {}
    for e in DATA:
        cats[e["category"]] = cats.get(e["category"], 0) + 1
    for c, n in cats.items():
        print(f"    {c}: {n}")


if __name__ == "__main__":
    main()
