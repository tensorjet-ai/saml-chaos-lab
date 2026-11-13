# saml-chaos-lab

> Deterministic open-core SAML 2.0 fault-injection runner for staging and CI Service Providers.

`saml-chaos-lab` spins up a signed, ephemeral SAML 2.0 Identity Provider locally, drives a real Chromium browser through your Service Provider's SSO login flow, and injects malformed or tampered assertions directly into your Assertion Consumer Service (ACS) to prove your SP fails closed before production rollouts.

[![npm version](https://img.shields.io/npm/v/saml-chaos-lab.svg)](https://www.npmjs.com/package/saml-chaos-lab)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> **Official npm packages:** **`saml-chaos-lab`** ([npm](https://www.npmjs.com/package/saml-chaos-lab)) and **`@tensorjetai/saml-chaos-lab`** ([npm](https://www.npmjs.com/package/@tensorjetai/saml-chaos-lab)).

---

## Quick Start

Because `saml-chaos-lab` drives real Chromium redirects, HTTP POST bindings, and session cookies to verify what your Service Provider actually accepts in a browser, install Playwright Chromium once on your machine or CI runner before running `test`:

```bash
# 1. Install Playwright Chromium (one-time per machine/runner)
npx playwright install chromium

# 2. Generate ephemeral IdP keys, local runner state (.saml-chaos-lab/), and SAML metadata
npx saml-chaos-lab metadata --out ./idp-metadata.xml

# 3. Upload ./idp-metadata.xml to your staging/local Service Provider, then run baseline checks
npx saml-chaos-lab test \
  --login-url http://127.0.0.1:4000/sso/login \
  --acs-url http://127.0.0.1:4000/saml/acs \
  --sp-entity-id urn:example:staging-sp \
  --success-url "^http://127\\.0\\.0\\.1:4000/app$" \
  --fail-on high
```

You can also invoke the org-scoped package alias directly:

```bash
npx @tensorjetai/saml-chaos-lab --help
```

---

## The Problem: Why Happy-Path SAML Tests Miss Auth Bypasses

Standard integration suites only verify that a valid signed login redirects to `/dashboard`. They rarely prove what happens when an attacker tampers with assertions in flight or reuses mis-scoped responses:

1. **Missing Conditions Window Checks (`SAML-TIME-001`)**: Service Providers that ignore `<Conditions NotOnOrAfter="...">` accept captured assertions indefinitely after they expire.
2. **Missing Audience Restriction Checks (`SAML-AUD-001`)**: Without strict `<Audience>` matching against your SP Entity ID, assertions minted for another application integrated with the same IdP can authenticate into yours.
3. **Missing Destination Validation (`SAML-DEST-001`)**: Accepting responses with mismatched `Destination` attributes enables assertion replay across endpoints or environments.
4. **Trusting Unverified IdP Issuers (`SAML-ISS-001`)**: Skipping strict `<Issuer>` pinning allows multi-tenant or shared IdP issuers to spoof trust.
5. **Accepting Post-Signature Modifications (`SAML-SIG-001`)**: Parsing XML attributes before validating XMLDSIG integrity or digest references lets attackers alter `NameID` values inside previously signed payloads.

---

## Features

- **Ephemeral In-Process SAML 2.0 IdP**: Provisions fresh RSA signing certificates on `127.0.0.1` via Fastify, emits standard SAML 2.0 metadata XML (`idp-metadata.xml`), and tears down automatically after each run.
- **Real Browser Assertion Execution**: Uses Playwright Chromium rather than synthetic HTTP mocks so HTTP redirects, `RelayState`, ACS POST forms, session cookies, and post-login DOM selectors are verified end-to-end.
- **Fail-Closed Baseline Gating**: Runs `SAML-BASE-001` first; if baseline login itself fails or redirects off-origin, remaining fault injections do not mask a broken test setup.
- **Pinned SSRF & Request Guardrails**: Pre-resolves and pins target IP addresses, blocks unauthorized subresource or redirect origins, and scopes single-use HMAC activation tokens to `(project, run, scenario, browserSessionId)`.
- **CI Native Reporting**: Outputs a Markdown results table to `stdout` and automatically appends it to `$GITHUB_STEP_SUMMARY` when running inside GitHub Actions.

---

## CLI Usage

### 1. `saml-chaos-lab metadata`

Generates an ephemeral current and next X.509 certificate pair, reserves a local ephemeral port on `127.0.0.1`, writes runner state under `--state-dir` (mode `0600`), and outputs standard IdP `EntityDescriptor` XML for your Service Provider configuration.

```bash
npx saml-chaos-lab metadata --out ./idp-metadata.xml
```

| Option              | Required | Default              | Description                                                                  |
| :------------------ | :------- | :------------------- | :--------------------------------------------------------------------------- |
| `--out <file>`      | No       | `./idp-metadata.xml` | Destination file path for generated SAML 2.0 IdP metadata XML.               |
| `--state-dir <dir>` | No       | `.saml-chaos-lab`    | Directory where ephemeral port and signing state (`runner.json`) are stored. |

### 2. `saml-chaos-lab test`

Reads runner state created by `metadata`, starts the ephemeral IdP on `127.0.0.1`, launches headless Chromium, and executes all 6 open-core baseline scenarios sequentially.

```bash
npx saml-chaos-lab test \
  --login-url http://127.0.0.1:4000/sso/login \
  --acs-url http://127.0.0.1:4000/saml/acs \
  --sp-entity-id urn:example:staging-sp \
  --success-url "^http://127\\.0\\.0\\.1:4000/app$" \
  --dom-selector "[data-testid='authenticated-user']" \
  --fail-on high
```

| Option                    | Required | Default           | Description                                                                      |
| :------------------------ | :------- | :---------------- | :------------------------------------------------------------------------------- |
| `--login-url <url>`       | **Yes**  | —                 | SP login entry URL that initiates SAML `AuthnRequest` redirects.                 |
| `--acs-url <url>`         | **Yes**  | —                 | SP Assertion Consumer Service endpoint expecting `POST` SAML responses.          |
| `--sp-entity-id <id>`     | **Yes**  | —                 | Expected Service Provider `EntityID` / Audience URI.                             |
| `--success-url <pattern>` | **Yes**  | —                 | Regular expression matching the post-login authenticated URL (evaluated safely). |
| `--dom-selector <css>`    | No       | —                 | Optional CSS selector required to appear after a successful login.               |
| `--fail-on <level>`       | No       | `high`            | Exit with code `1` if any failed scenario meets `high` or `critical`.            |
| `--state-dir <dir>`       | No       | `.saml-chaos-lab` | State directory created by `saml-chaos-lab metadata`.                            |

### Exit Codes

| Code | Meaning                                                                                                                                |
| :--- | :------------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | Valid baseline succeeded and all negative baseline attacks were properly rejected by the SP.                                           |
| `1`  | One or more negative security checks failed (the SP accepted an invalid/tampered assertion) at or above `--fail-on`.                   |
| `2`  | Invalid arguments, missing `metadata` state, target blocked/unreachable, broken baseline (`SAML-BASE-001`), or inconclusive execution. |

---

## Baseline Scenario Catalog (6 Deterministic Checks)

| Scenario ID     | Scenario Name              | Expected SP Outcome | Severity     | Remediation Guidance                                                                                     |
| :-------------- | :------------------------- | :------------------ | :----------- | :------------------------------------------------------------------------------------------------------- |
| `SAML-BASE-001` | Valid baseline response    | `accept`            | **Info**     | Verify valid SAML login succeeds before running fault injections.                                        |
| `SAML-TIME-001` | Expired assertion          | `reject`            | **Critical** | Enforce `<Conditions NotOnOrAfter>` with documented bounded clock skew.                                  |
| `SAML-AUD-001`  | Wrong audience             | `reject`            | **Critical** | Match `<Audience>` strictly to your configured SP Entity ID.                                             |
| `SAML-DEST-001` | Wrong response destination | `reject`            | **Critical** | Match `Response/@Destination` strictly to your ACS URL.                                                  |
| `SAML-ISS-001`  | Wrong issuer               | `reject`            | **Critical** | Pin and verify trusted IdP `<Issuer>` values strictly.                                                   |
| `SAML-SIG-001`  | Post-signature mutation    | `reject`            | **Critical** | Validate XML signature and digest reference integrity before consuming assertion attributes or `NameID`. |

---

## CI/CD Pipeline Integration

Gate pull requests in GitHub Actions against your local or ephemeral staging SP:

```yaml
name: SAML Chaos Lab Baseline

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  saml-baseline:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Install Playwright Chromium
        run: npx --yes playwright@1.61.1 install --with-deps chromium

      - name: Provision IdP Metadata & Start Test SP
        run: |
          npx --yes saml-chaos-lab@0.1.0 metadata --out ./idp-metadata.xml
          # Start your SP configured with ./idp-metadata.xml in the background

      - name: Run Baseline SAML Security Checks
        run: |
          npx --yes saml-chaos-lab@0.1.0 test \
            --login-url http://127.0.0.1:4000/sso/login \
            --acs-url http://127.0.0.1:4000/saml/acs \
            --sp-entity-id urn:example:staging-sp \
            --success-url "^http://127\\.0\\.0\\.1:4000/app$" \
            --fail-on high
```

Prefer running without installing Chromium on the host? Use the Apache-2.0 [`Dockerfile.runner`](https://github.com/tensorjetai/saml-chaos-lab/blob/main/Dockerfile.runner) or composite GitHub Action from the source repository.

---

## Open-Core vs. Commercial Pro Edition

| Capability                                                  | Open-Core CLI (`saml-chaos-lab` on npm)                                             | Commercial Container (`registry.tensorjetai.com/saml-chaos-lab-commercial`) |
| :---------------------------------------------------------- | :---------------------------------------------------------------------------------- | :-------------------------------------------------------------------------- |
| License                                                     | `Apache-2.0`                                                                        | Commercial License (`UNLICENSED`, offline Ed25519 `TJ_LICENSE_KEY`)         |
| Baseline Hygiene Suite (6 checks)                           | Included (`SAML-BASE-001`, `TIME-001`, `AUD-001`, `DEST-001`, `ISS-001`, `SIG-001`) | Included                                                                    |
| XML Signature Wrapping (XSW 1–10)                           | —                                                                                   | Included (`SAML-XSW-001` .. `SAML-XSW-010`)                                 |
| C14N Comment/PI/Void Canonicalization                       | —                                                                                   | Included (`SAML-C14N-001` .. `SAML-C14N-003`)                               |
| Differential Parser & DTD/XSLT Probes                       | —                                                                                   | Included (`SAML-DIFF-*`, `SAML-XML-*`)                                      |
| Replay, Clock Skew, Dual-Key Cert Rollover & Binding Checks | —                                                                                   | Included (`SAML-REPLAY-001`, `TIME-*`, `CERT-*`, `SIG-002`, `FLOW-*`)       |
| Audit Reports & Artifact Integrity                          | Stdout & GitHub Step Summary Markdown                                               | SHA-256 Tamper-Evident JSON, Self-Contained HTML, SARIF 2.1.0               |
| Distribution                                                | `npx saml-chaos-lab`                                                                | Multi-arch (`amd64`/`arm64`) hardened Docker image with bundled Chromium    |

Pull the commercial edition after checkout at [saml.tensorjetai.com](https://saml.tensorjetai.com):

```bash
echo "$TJ_LICENSE_KEY" | docker login registry.tensorjetai.com -u license --password-stdin
docker pull registry.tensorjetai.com/saml-chaos-lab-commercial:0.1.0
```

---

## Safety Model & Limitations

- **Authorized Staging Targets Only**: Run SAML Chaos Lab solely against local or staging Service Providers you own or have explicit written permission to test. Never run fault-injection tests against production SSO endpoints.
- **Synthetic Identity Only**: All assertions issue a fixed synthetic principal (`synthetic-user@invalid.example`), never real workforce credentials.
- **Zero-Egress Runtime**: The CLI and its ephemeral IdP run 100% locally with zero telemetry or target data sent to TensorJet servers.
- **Network & Origin Guardrails**: Target URLs are pre-resolved and pinned against unexpected DNS rebinding, and browser requests are restricted to configured origins.
- **Evidence, Not Certification**: Passing baseline checks provides deterministic regression evidence against tested scenarios, not an exhaustive security certification or formal audit across all possible SP parsers.

---

## Links & Ecosystem

- **Homepage & Pricing**: [saml.tensorjetai.com](https://saml.tensorjetai.com)
- **Organization**: [TensorJetAI](https://github.com/tensorjetai) · [tensorjetai.com](https://tensorjetai.com)
- **GitHub Repository**: [github.com/tensorjetai/saml-chaos-lab](https://github.com/tensorjetai/saml-chaos-lab)
- **Issues & Support**: [github.com/tensorjetai/saml-chaos-lab/issues](https://github.com/tensorjetai/saml-chaos-lab/issues)
- **Scoped npm Alias**: [`@tensorjetai/saml-chaos-lab`](https://www.npmjs.com/package/@tensorjetai/saml-chaos-lab)

---

## License

[Apache-2.0](LICENSE) © 2026 TensorJetAI
