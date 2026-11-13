# Local CI Runner

Run the open-core 6-check baseline SAML suite locally or in CI without Docker Compose:

```bash
pnpm --filter saml-chaos-lab build
node packages/cli/bin/saml-chaos-lab.mjs metadata --out ./idp-metadata.xml
node packages/cli/bin/saml-chaos-lab.mjs test \
  --login-url https://staging.example.com/sso/login \
  --acs-url https://staging.example.com/saml/acs \
  --sp-entity-id urn:example:staging-sp \
  --success-url "^https://staging\\.example\\.com/app$"
```

Exit codes:

- `0`: all executed checks passed within threshold
- `1`: a finding met or exceeded `--fail-on` (`high` or `critical`)
- `2`: target blocked, unreachable, invalid arguments, or inconclusive run

For the full 33-scenario adversarial CVE suite (XSW 1–10, C14N comment truncation/PI/void canonicalization, DTD/XSLT probes, replay, cert rollover) and SHA-256 tamper-evident JSON/HTML/SARIF compliance reports, pull the commercial container from `registry.tensorjetai.com/saml-chaos-lab-commercial:0.1.1`.
