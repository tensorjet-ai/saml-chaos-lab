# Service-provider configuration

1. Create a staging-only project and enter the exact login-start and ACS URLs.
2. Publish the supplied DNS TXT record or HTTPS well-known challenge for every target host (login-start, ACS, and each allowlisted redirect host). Runs stay blocked until all of them verify; ownership re-verifies every 30 days.
3. Import the project metadata URL into the staging SP.
4. Configure the IdP entity ID and Redirect SSO URL exactly as shown in metadata.
5. Require signed assertions using RSA-SHA256. Trust both metadata certificates during rollover overlap.
6. Map the displayed synthetic NameID and attributes to a disposable staging account.
7. Configure a success URL expression and optional DOM selector.
8. Run baseline. Negative scenarios remain blocked until baseline passes.

The lab accepts SP-initiated HTTP-Redirect `AuthnRequest` and returns HTTP-POST `SAMLResponse`. Encrypted assertions, IdP-initiated SSO, SLO, SHA-1, and production endpoints are unsupported.
