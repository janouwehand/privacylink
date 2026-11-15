# ADR 0002: Optional password and email access protection

- Status: Adopted (retrospective reconstruction)
- Record date: 2026-11-15

## Decision

Keep the client key as the content-decryption secret and offer two optional server-enforced access checks:

- For a PIN or password, the browser derives an HMAC-SHA-256 token from the entered value and the client key. The API uses that token with a server-side pepper and Argon2id to derive a key that wraps the already client-encrypted content with AES-256-GCM. On unlock, the API unwraps the client ciphertext; the browser still decrypts the content with the key from the link.
- For email verification, the recipient requests a six-digit one-time code for the sender-configured mailbox. A successful code grants a fixed 30-minute, secret-bound session through an HttpOnly cookie. Email verification is an access gate, not a content-encryption key; the email address remains readable server metadata. Email and password checks may both be enabled, with email verification required first.

The server does not persist the entered password, password-derived token, or derived Argon2 key. It requires a configured pepper for password protection. Email OTP records and queued mail delivery use the database-backed verification and encrypted outbox flow.

## Context and consequences

The additional checks reduce the risk that possession of a leaked share link alone is enough to retrieve ciphertext. The password envelope also requires the server's pepper to unwrap its outer layer. These controls create operational dependencies: losing the pepper makes still-stored password-protected secrets unrecoverable; email verification depends on PostgreSQL, secret configuration, and mail delivery. OTP delivery proves access to the configured mailbox at that time, not the recipient's identity in a broader sense. Neither control protects content after the client key and content are available to a recipient or a compromised browser.

The exact historical motivation for adding these factors is not documented in the repository. This decision records the current separation of responsibilities and its observable tradeoffs.

## Evidence

- [Password envelope service](../../src/PrivacyLink.Services/PasswordEnvelopeService.cs)
- [Email verification service](../../src/PrivacyLink.Services/EmailVerification.cs)
- [Email verification specification](../email-verification-spec.md)
- [Runbook configuration and operational requirements](../runbook.md)
- [Security details presented by the app](../../src/PrivacyLink.Web/src/app/security/security-details-page.ts)
