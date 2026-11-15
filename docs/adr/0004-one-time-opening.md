# ADR 0004: Atomic one-time opening

- Status: Adopted (retrospective reconstruction)
- Record date: 2026-11-15

## Decision

Allow senders to mark a secret for one-time opening. After the required access checks pass, atomically and durably mark the secret as consumed before returning its ciphertext. A competing request or later request cannot retrieve it again, including after a restart or through another API instance. After the complete response is written successfully, delete the associated blobs and metadata. If delivery is interrupted after consumption, keep the secret inaccessible and let revocation or expiry cleanup remove any remaining stored material.

Existing secrets and newly created reusable secrets retain repeat-open behavior unless the sender chooses one-time opening.

## Context and consequences

Durable atomic consumption prevents two concurrent requests or multiple server instances from both treating the same one-time secret as available. Marking it consumed before sending avoids re-opening after a response might have partially exposed content. The cost is availability: a broken connection can consume the one opening before the recipient receives all bytes. The server cannot prove that the recipient did not save or copy content after receiving it. Physical blob deletion also does not remove backups or guarantee storage-media overwrite.

The repository records the current mechanism and its failure behavior. It does not preserve a contemporaneous rationale for choosing one-time use or the precise response-write boundary.

## Evidence

- [Secret opening and consumption](../../src/PrivacyLink.Services/SecretApplicationService.cs)
- [Persistent one-time state and atomic consume](../../src/PrivacyLink.Infrastructure/Persistence.cs)
- [Response completion cleanup](../../src/PrivacyLink.Api/OneTimeOpenCleanupResult.cs)
- [One-time open operational behavior](../runbook.md)
- [Security details presented by the app](../../src/PrivacyLink.Web/src/app/security/security-details-page.ts)
