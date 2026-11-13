# Quickstart

Run SAML Chaos Lab's open-core baseline suite locally against an ephemeral staging or fixture Service Provider:

1. Install workspace dependencies:

   ```bash
   pnpm install
   ```

2. Build the CLI binary:

   ```bash
   pnpm build
   ```

3. Generate IdP metadata for your staging Service Provider:

   ```bash
   node packages/cli/bin/saml-chaos-lab.mjs metadata --out ./idp-metadata.xml
   ```

4. Run the 6 baseline checks (`SAML-BASE-001`, `SAML-TIME-001`, `SAML-AUD-001`, `SAML-DEST-001`, `SAML-ISS-001`, `SAML-SIG-001`):

   ```bash
   node packages/cli/bin/saml-chaos-lab.mjs test \
     --login-url http://127.0.0.1:4000/login \
     --acs-url http://127.0.0.1:4000/saml/acs \
     --sp-entity-id urn:fixture:sp \
     --success-url "^http://127\\.0\\.0\\.1:4000/success$"
   ```
