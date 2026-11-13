# Troubleshooting

## Baseline fails

Confirm entity ID, ACS URL, IdP metadata, certificate trust, synthetic-user mapping, success URL pattern, and browser host allowlist. Do not interpret negative scenarios until baseline passes.

## Ownership challenge fails

Query the exact TXT record from a public resolver, join split TXT fragments, or confirm the HTTPS well-known body contains only the token. Challenges expire after 15 minutes and are single-use.

## Signature rejected

Require RSA-SHA256 and SHA-256 digest support, import the full current certificate, preserve XML bytes through HTTP-POST decoding, and verify the assertion reference—not an unsigned duplicate node.

## Rollover fails

Refresh metadata, retain current and next certificates during overlap, and promote only after the SP accepts next-certificate signatures.

## Run stays queued

Check worker `/ready`, queue depth, lease-expiry metrics, PostgreSQL connectivity, Playwright Chromium installation, and project active-run uniqueness.

## Service exits during startup

Persistent mode intentionally rejects partial security configuration. Check `IDP_INTERNAL_URL`, `INTERNAL_SERVICE_TOKEN`, `ACTIVATION_SECRET`, and `MASTER_KEY_BASE64`. Hosted API mode also requires `INVITE_TOKEN`; local-target development may explicitly set `ALLOW_LOCAL_TARGETS=true`.
