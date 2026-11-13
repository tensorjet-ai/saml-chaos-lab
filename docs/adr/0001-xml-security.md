# ADR 0001: XML signature and parsing dependencies

Status: accepted — 2026-07-16

## Decision

Pin `xml-crypto` 6.1.2 for XMLDSIG signing/verification and `@xmldom/xmldom` 0.9.10 for DOM handling. Use `fast-xml-parser` 5.10.1 only after rejecting any input containing `DOCTYPE` or `ENTITY`; never resolve DTDs or external entities. Restrict algorithms to RSA-SHA256, SHA-256 digests, exclusive canonicalization, and enveloped signatures.

## Rationale

`xml-crypto` exposes the required algorithms and reference validation while delegating primitives to Node's audited crypto implementation. Explicit reference selection and validation support safe post-sign mutation tests. Exact version pins and lockfile integrity limit supply-chain drift.

## Rejected alternatives

- `samlify`: broader protocol abstraction obscures intentional malformed-response generation.
- `passport-saml`: SP authentication middleware, not a controlled IdP response engine.
- Hand-written canonicalization/signature code: unacceptable interoperability and security risk.

## Consequences

Every signed document receives known-answer and tamper-rejection coverage. Parser entry points reject DTD/entity declarations, enforce byte limits, and bind IDs before trusting fields.
