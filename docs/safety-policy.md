# Safety and authorization policy

Use SAML Chaos Lab only against staging systems you own or are explicitly authorized to test. Production targets and real credentials are prohibited.

Hosted delivery requires hostname ownership verification, exact ACS binding, HTTPS, public DNS, pre-run and immediate per-request resolution, pinned HTTPS verification sockets, Chromium socket pinning, exact-origin redirect allowlisting, bounded bodies and redirects, and synthetic identities. Loopback, private, link-local, multicast, metadata-service, transition/NAT64, IP-literal, rebinding, expired ownership, unverified, and mismatched destinations fail closed.

Activation tokens are short-lived, HMAC-signed, single-use, and scoped to project, run, scenario, and browser session. Browser navigation is restricted to configured hosts. DTD and entity declarations are rejected before XML parsing.

Report suspected abuse or key exposure through the incident contact configured by the operator. Stop worker egress immediately, revoke the affected project certificate, preserve redacted audit metadata, and rotate activation/master keys.
