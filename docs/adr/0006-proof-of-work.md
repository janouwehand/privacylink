# ADR 0006: Proof of work and layered abuse controls

- Status: Adopted (retrospective reconstruction)
- Record date: 2026-11-15

## Decision

Require short, server-verified proof-of-work challenges for secret creation and for recipient operations that retrieve content: open, unlock, and per-file retrieval. The browser computes the SHA-256 puzzle asynchronously. Challenges are HMAC-signed by the server, expire, and their valid proofs are accepted only once through bounded replay storage. Open proofs are bound to a secret and operation. Challenge endpoints have separate per-effective-IP rate limits.

Treat proof of work as one layer alongside request validation and limits, file and body size bounds, storage limits, and operation-specific rate limits. It raises the cost of simple automated clients that do not implement the protocol; it is not authentication, evidence of a human, or DDoS protection. Difficulty requires measurement on supported phones and under server load before production tuning.

## Context and consequences

Proof of work moves some cost to the client and can reject missing or invalid proofs before the application parses a create request body. On recipient routes it adds per-secret, per-operation effort, but a client that has the link can still solve the puzzle and open the secret. Challenge generation, replay protection, shared keys, difficulty configuration, and mobile performance introduce operational complexity. Reverse proxies may buffer request bytes before application validation, and traffic can still consume network and proxy resources.

The protocol specifications and runbook establish the current scope and known limits. The repository does not establish a contemporaneous analysis proving that proof of work is preferable to other anti-abuse options or that the configured difficulty is calibrated for production.

## Evidence

- [Create proof specification](../proof-of-work.md)
- [Create proof implementation](../../src/PrivacyLink.Api/CreateProofOfWork.cs)
- [Open proof implementation](../../src/PrivacyLink.Api/OpenProofOfWork.cs)
- [Replay store](../../src/PrivacyLink.Infrastructure/CreateProofReplayStore.cs)
- [Production configuration and limitations](../runbook.md)
- [Protocol integration tests](../../tests/PrivacyLink.IntegrationTests/CreateProofTestSupport.cs)
