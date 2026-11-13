# SAML Chaos Lab

> Deterministic open-core SAML 2.0 fault-injection runner for staging and CI Service Providers.

`saml-chaos-lab` spins up a signed, ephemeral SAML 2.0 Identity Provider locally, drives a real Chromium browser through your Service Provider's SSO login flow, and injects malformed or tampered assertions directly into your Assertion Consumer Service (ACS) to prove your SP fails closed before production rollouts.

[![npm version](https://img.shields.io/npm/v/saml-chaos-lab.svg)](https://www.npmjs.com/package/saml-chaos-lab)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

> **Official npm packages:** **`saml-chaos-lab`** ([npm](https://www.npmjs.com/package/saml-chaos-lab)) and **`@tensorjetai/saml-chaos-lab`** ([npm](https://www.npmjs.com/package/@tensorjetai/saml-chaos-lab)).

---

## Quick Start (npm CLI)

Because `saml-chaos-lab` drives real Chromium redirects, HTTP POST bindings, and session cookies to assert what your Service Provider accepts in a browser, install Playwright Chromium once on your machine or CI runner before running `test`:

```bash
npx playwright install chromium
npx saml-chaos-lab metadata --out ./idp-metadata.xml
npx saml-chaos-lab test \
  --login-url http://127.0.0.1:4000/sso/login \
  --acs-url http://127.0.0.1:4000/saml/acs \
  --sp-entity-id urn:example:staging-sp \
  --success-url "^http://127\\.0\\.0\\.1:4000/app$" \
  --fail-on high
```

See the full CLI flag reference, CI workflow example, and scenario catalog in [`packages/cli/README.md`](packages/cli/README.md).

---

## What Is Included (Apache-2.0 Open-Core)

- **Ephemeral SAML 2.0 IdP Simulator** (`apps/idp`) & **SAML Core** (`packages/saml-core`)
- **SSRF Target Safety & IP Pinning** (`packages/target-safety`) & **Redacted Observability** (`packages/observability`)
- **Playwright Browser Assertion Runner** (`packages/browser-runner`)
- **CLI Package** (`packages/cli` → `saml-chaos-lab`)
- **6 Baseline Hygiene Checks** (`packages/scenarios`):
  - `SAML-BASE-001` (`info`): Valid baseline response (`accept`)
  - `SAML-TIME-001` (`critical`): Expired assertion rejection (`reject`)
  - `SAML-AUD-001` (`critical`): Wrong Audience restriction rejection (`reject`)
  - `SAML-DEST-001` (`critical`): Wrong Response Destination rejection (`reject`)
  - `SAML-ISS-001` (`critical`): Wrong Issuer rejection (`reject`)
  - `SAML-SIG-001` (`critical`): Post-signature assertion tampering rejection (`reject`)

---

## Commercial / Pro Edition

The full **33-scenario adversarial CVE suite** (`SAML-XSW-001..010`, `SAML-C14N-001..003`, `SAML-DIFF-*`, `SAML-XML-*`, `SAML-FLOW-*`, `SAML-CERT-*`, `SAML-REPLAY-001`), SHA-256 tamper-evident JSON/HTML/SARIF audit reports, and offline Ed25519 license verification are distributed via `registry.tensorjetai.com/saml-chaos-lab-commercial:0.1.0` ([saml.tensorjetai.com](https://saml.tensorjetai.com)):

```bash
echo "$TJ_LICENSE_KEY" | docker login registry.tensorjetai.com -u license --password-stdin
docker pull registry.tensorjetai.com/saml-chaos-lab-commercial:0.1.0
```

---

## Local Development

```bash
pnpm install
pnpm typecheck
pnpm build
pnpm test
pnpm test:e2e
```

See [Local CI Runner](docs/local-ci-runner.md), [SP configuration](docs/sp-configuration.md), and [Safety policy](docs/safety-policy.md) for architecture and usage details.
