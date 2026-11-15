# ADR 0003: Secret request auditing and privacy

- Status: Adopted (retrospective reconstruction)
- Record date: 2026-11-15

## Decision

Record each HTTP request that the application classifies as concerning a secret, including rejected and failed requests. In production, persist request metadata in PostgreSQL: action, secret ID, route and method, timestamps, outcome, status, trace ID, client IP, and a file ID where applicable. Keep audit rows after secret deletion and retain them without a time limit. Do not store request bodies, passwords, or encryption keys in this audit table. Limit access to the authenticated admin view and authorized database operators; there is no public audit API.

Application privacy audit logs separately record operation, status, trace ID, duration, and a truncated HMAC of the client IP when configured. The secret-request table stores the normalized effective client IP in readable form. In-memory audit storage is used in development without PostgreSQL.

## Context and consequences

Per-request records support investigation of failed, abusive, and successful secret operations, including requests whose secret has since been removed. This creates a persistent personal-data store: the readable IP and request history can be correlated over time, and deletion of a secret does not remove those records. Access controls and application-level omission of content and credentials reduce exposure but do not remove the retention and privacy impact. Hosting and proxy logs follow separate policies.

The repository documents unlimited retention as the current policy but does not establish the original retention analysis, legal basis, or intended review period. Those remain governance questions for the service owner; this ADR records observed behavior and should not be read as independent legal approval.

## Evidence

- [Request audit specification](../new-stats-audit.md)
- [Audit middleware](../../src/PrivacyLink.Api/SecretRequestAuditMiddleware.cs)
- [Audit repository](../../src/PrivacyLink.Infrastructure/SecretRequestAuditRepository.cs)
- [Admin authentication and audit access](../../src/PrivacyLink.Api/AdminAuthentication.cs)
- [Production runbook](../runbook.md)
- [Application security details](../../src/PrivacyLink.Web/src/app/security/security-details-page.ts)
