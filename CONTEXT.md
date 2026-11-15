# PrivacyLink context

PrivacyLink is a prototype for sharing text and files without accounts. The browser encrypts content before upload; the API stores and serves ciphertext with the metadata and access controls required to create, locate, limit, open, and delete a secret.

## Domain terms

- **Secret**: the server-side record and encrypted content associated with one share.
- **Share link**: the recipient URL. Its fragment carries the client key and is not sent in the HTTP request.
- **Client key**: a random browser-generated key used for client-side content encryption and decryption.
- **Sender history**: encrypted, browser-local records that let the sender retrieve a share link and related access material.
- **Revoke token**: a random capability returned at creation and required to revoke a secret; the server stores its hash.

## Trust and security boundaries

The browser holds the client key and encrypts/decrypts message and file content. The API receives ciphertext, but it also processes readable metadata and may apply additional access gates, audit requests, and enforce expiry, revocation, and one-time-use rules. A compromised app origin or endpoint can expose data available to its browser; server-side ciphertext storage does not protect against malicious JavaScript served to a recipient.

The application is not an anonymity, availability, malware-scanning, or post-disclosure control. Recipients can retain content after opening it. Deployment controls such as TLS termination, proxy logs, infrastructure access, backups, and physical storage protection remain outside the application-level encryption guarantee.

## Architectural decisions

These ADRs record decisions reconstructed from the current implementation, specifications, tests, deployment documentation, and repository history. They were written retrospectively on 2026-11-15; that date is the record date, not the date each design was originally chosen. Historical discussions or rationales that could not be established from repository evidence are called out as such.

- [ADR 0001: Client-side encryption and link trust boundary](docs/adr/0001-client-side-encryption.md)
- [ADR 0002: Optional password and email access protection](docs/adr/0002-additional-access-protection.md)
- [ADR 0003: Secret request auditing and privacy](docs/adr/0003-secret-request-audit-and-privacy.md)
- [ADR 0004: Atomic one-time opening](docs/adr/0004-one-time-opening.md)
- [ADR 0005: Encrypted browser-local sender history](docs/adr/0005-sender-history.md)
- [ADR 0006: Proof of work and layered abuse controls](docs/adr/0006-proof-of-work.md)
