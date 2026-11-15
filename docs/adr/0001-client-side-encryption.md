# ADR 0001: Client-side encryption and the link trust boundary

- Status: Adopted (retrospective reconstruction)
- Record date: 2026-11-15

## Decision

The browser encrypts message and file content with AES-256-GCM before upload. It derives purpose-specific keys from a random 256-bit client key with HKDF-SHA-256. The client key is carried in the share link's URL fragment, which browsers do not include in HTTP requests. The API stores and returns ciphertext and does not receive that key. The browser performs content decryption after retrieval.

The server may see or store metadata needed to operate the service, including secret IDs, expiry, file count, file extension, MIME type, declared size, and optional email address. The filename stem is encrypted client-side. Password protection adds a separate server-side envelope around client ciphertext, but the client key remains necessary to decrypt the content.

## Context and consequences

This design limits the content available to a database or blob-store reader that lacks the client key. It also means server-side code cannot inspect content for malware or moderation, and visible metadata and traffic patterns remain exposed. A recipient's complete share link contains the client key and must be treated as secret. A compromised browser, app origin, endpoint, or malicious frontend can access keys when used; the design does not protect a compromised client device.

The implementation uses Web Crypto in the shared TypeScript client and browser clients. Changing key derivation, authenticated data, ciphertext formats, or link transport can affect existing links, so protocol compatibility must be considered explicitly.

## Historical uncertainty

The repository supports this boundary as the implemented design. It does not contain a contemporaneous record establishing when or why the URL-fragment approach was selected, nor a complete threat model from the original design discussion. The rationale above describes the security property and tradeoffs inferred from the implementation; it is not a claim about undocumented historical deliberation.

## Evidence

- [Client cryptography](../../src/PrivacyLink.Client/src/secret-crypto.ts)
- [Security details presented by the app](../../src/PrivacyLink.Web/src/app/security/security-details-page.ts)
- [README security description](../../README.md)
