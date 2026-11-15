# PrivacyLink Security Whitepaper

- **Status:** Living technical description, maintained with the application.
- **Language:** English.

| Item | Description |
| --- | --- |
| Scope | PrivacyLink's first-party browser application and the API it uses to create and open shares |
| Not covered | The separate third-party text-creation API, a specific public deployment, hosting provider, reverse proxy, external mail provider, or independent security assessment |
| Evidence basis | Current repository implementation, checked-in tests, configuration defaults, and operational documentation |

This document describes the implementation represented by the repository from which the website is built. It does not identify or prove the software revision or configuration running at a live service. A code-level fact may differ from production behavior. No independent cryptographic audit or security certification is claimed.

## 1. Summary

PrivacyLink lets a sender share a message or files through a link without creating an account. The sender's browser encrypts the message and file contents before sending them to the service. The decryption key is carried in the link fragment, after the `#` character. A normal HTTP request does not include that fragment, but the web application running in the browser can read it.

The API stores encrypted content and readable metadata used to manage a share. In a database-backed installation, metadata is stored in PostgreSQL and encrypted blobs are stored under a configured filesystem path. Development can use in-memory storage. Optional access-code protection adds an outer encryption layer that the API can remove after the correct code-derived proof is supplied; the inner browser encryption remains in place. Optional email verification checks access to a specified mailbox. One-time opening prevents the service from returning the content through a later request after the first authorized opening is consumed.

These controls do not protect against a compromised device or browser, malicious code delivered by the website, someone who obtains the complete link, or a recipient who saves or shares content after opening it. Expiry and revocation do not retrieve copies already received.

## 2. Security goals and limits

### Intended protections

- A person who can read the stored content bytes but does not have the client key cannot use those bytes alone to decrypt message and file contents.
- AES-GCM authentication detects changes to encrypted content and to the file fields bound to that content.
- The API applies expiry, revocation, optional access checks, one-time-use rules, request limits, and abuse controls.
- The client key is kept out of ordinary HTTP requests by placing it in the link fragment.

### Assumptions and exclusions

The design assumes that the sender and recipient use a trustworthy device and browser, receive the expected website code, and have a correctly secured HTTPS connection. The service operator controls the web origin and can change the JavaScript sent to users. A malicious or compromised version of that code could read a key or plaintext while the application is in use.

PrivacyLink does not promise anonymity, uninterrupted availability, protection from traffic analysis, malware scanning of encrypted files, or confidentiality after a recipient has opened content. The application does not promise encryption of database volumes, disks, filesystem storage, backups, or snapshots. Hosting access, proxy and platform logs, backup retention, network monitoring, and physical infrastructure require separate assessment.

Encrypted file contents cannot be inspected by the API for malware or their actual format. A file extension, declared MIME type, and declared size do not prove that a file is safe. Recipients should treat downloaded files as untrusted.

## 3. Data flow and trust boundaries

1. The sender's browser generates a random client key and encrypts the message and each file locally.
2. The browser sends encrypted content and the metadata needed to create the share to the API.
3. The API stores metadata and encrypted payloads, applies access and lifecycle rules, and returns the share identifier, expiry time, and a separate revocation token. The browser combines the identifier with the client key to construct the share link.
4. The sender shares the complete link with the recipient. The client key is in its fragment and is not sent in ordinary HTTP requests.
5. After the recipient opens the link, the browser retrieves the encrypted payload and decrypts it locally with the key from the fragment.

The fragment is hidden from ordinary HTTP requests, not from the user, the browser application, browser extensions, or a person who gets the full link. A share link must be treated as a secret. Browser history, clipboard contents, screenshots, link-preview services, extensions, or access to the browser profile can expose it.

### Information visible to the service

The API needs operational metadata even when it cannot decrypt the inner client-encrypted content. The repository implementation includes the following readable fields:

| Data | What the service can process or store |
| --- | --- |
| Share management | Share identifier, expiry time, whether a message exists, file count, access-code protection status, and one-time-open status |
| File metadata | File identifier, lower-case extension, declared MIME type, declared plaintext size, and an encrypted filename stem plus its nonce. The extension is readable; the stem is encrypted in the browser. |
| Email verification | The specified email address is readable server metadata and is shown in masked form in recipient-facing metadata. |
| Request activity | Secret-request audit records include such fields as action, outcome, time, route category, share identifier, and effective client IP. The IP is stored in readable form. |
| Network activity | The service can observe request timing and traffic patterns. Separate hosting, proxy, infrastructure, and monitoring logs are outside the application's logging behavior. |

Ciphertext lengths also reveal content sizes: AES-GCM adds a 16-byte tag, so the API can infer the message byte length from its encrypted payload. File size is also supplied as readable metadata and checked against the encrypted payload length.

When email verification is enabled, a verified email address is associated with the share. The service cannot inspect encrypted message text, encrypted file bytes, or the filename stem from the stored client ciphertext alone. A password-protected share adds an outer layer which the API can decrypt during authorized unlock, but the resulting content is still encrypted with the browser key.

## 4. Browser encryption protocol

The web client uses protocol version `1` and the Web Crypto API. Protocol fields use canonical, unpadded Base64URL encoding. The client key is 32 random bytes. Fresh 12-byte nonces are generated for AES-GCM operations; the 128-bit GCM authentication tag is included at the end of each ciphertext.

The key derivation uses HKDF with SHA-256, a 32-byte all-zero salt, and the client key as input key material. A separate context string is used for each purpose so that a message key, file-content key, and filename key are distinct.

| Item | Key derivation and authenticated data |
| --- | --- |
| Message | HKDF info: `privacylink-message-v1`; AES-GCM AAD: `privacylink:message:v1`; plaintext is the message encoded as UTF-8. |
| File content | A random 16-byte file ID is encoded as Base64URL. HKDF info: `privacylink-file:{id}`; AAD: `privacylink:file:{id}:{extension}:{mimeType}:{size}`. |
| Filename stem | The name before the extension is encrypted separately. HKDF info: `privacylink-filename:{id}:{extension}`; AAD: `privacylink:filename:{id}:{extension}:{mimeType}:{size}`. |

For file content and filename, each AES-GCM operation has its own fresh nonce. The file extension is normalized to lower case and the API checks it against a configured allowlist. The extension, MIME type, and declared size are not encrypted. After the browser decrypts the filename stem, it validates the name and adds the readable extension.

The client validates the lengths and canonical encoding of protocol identifiers, keys, nonces, and ciphertext fields. Decryption fails if the key is wrong, encrypted data is damaged, or authenticated file fields do not match. Unknown protocol versions are rejected rather than interpreted as version 1.

AES-GCM nonce uniqueness relies on secure random generation; the client does not persist a nonce counter. The protocol and existing links depend on the derivation contexts, authenticated-data strings, encodings, and payload format above. Changing them requires explicit compatibility and version handling.

## 5. Optional access-code protection

### How the code is used

The browser derives a token from the access code and client key. Specifically, it calculates HMAC-SHA-256 using the UTF-8 access code as the HMAC key and the 32-byte client key as the message. The literal code is not included in the API request; the derived token is.

The API uses its server-side pepper as the HMAC key and the received token as the message. It passes the resulting value through Argon2id to derive a 32-byte encryption key. Each share receives a random 16-byte salt. This key encrypts each already client-encrypted message or file with AES-256-GCM, using a separate random 12-byte nonce and a 16-byte tag per payload.

At unlock, the browser again sends a token derived from the code and client key. The API uses the configured pepper and stored salt to derive the envelope key, then removes the outer encryption layer. It returns the still client-encrypted content. The browser still needs the key in the share link to reveal the message and files.

The API stores the salt, outer nonces, and wrapped ciphertext, not the literal access code, received token, or derived Argon2id key. The browser clears the code input after use. The code is not an independent second factor if an attacker has both the complete share link and the code-derived token. Share the code through a channel separate from the link. The browser accepts any non-empty access code and does not enforce a minimum or maximum length on the original code. Use a long, unique code when the content warrants it; a short or predictable code is easier to guess if an attacker also obtains the share link and can make repeated attempts.

### Parameters, capacity, and failed attempts

Current repository defaults and bounds are:

| Setting | Default | Configurable range or behavior |
| --- | --- | --- |
| Argon2id memory | 65,536 KiB (64 MiB) | 8,192 KiB to 1,048,576 KiB |
| Argon2id iterations | 3 | 1 to 20 |
| Argon2id parallelism | 2 | 1 to 16 |
| Concurrent Argon2 operations | 2 per API process | 1 to 8 per process |
| Waiting unlocks | Up to 8 per process | 0 to 64; queued unlocks wait up to 30 seconds by default, configurable from 1 to 120 seconds |
| Access-code token accepted at creation | The browser derives a fixed 43-character Base64URL token from a 32-byte HMAC-SHA-256 result. | The API checks the token string against a default 4–256 UTF-16 code-unit bound and a 1,024-byte maximum (four times the configured maximum length). These checks apply to the derived token, not to the access code typed by the user. |
| Wrong unlock attempts | 5 per share in a 15-minute window | Attempt count, window, and cooldown are configurable; defaults are five attempts, 15 minutes, and a 15-minute cooldown. |

Protected creation does not wait in a queue. An unlock can wait in the bounded queue. When capacity is exhausted or a queue wait expires, the request receives a temporary-unavailable response and may be retried after the indicated delay. A password attempt limit is enforced per share in persistent storage and shared across API instances using PostgreSQL. API request-rate limits also apply by effective client IP. Argon2 work already started cannot be cancelled by the underlying library; after a disconnect it can continue using capacity until it finishes, after which the derived key is cleared and further blob processing is skipped.

The pepper is a required production secret kept outside version-controlled configuration. Every API instance that serves a share must use the same value. Losing it makes still-stored password-protected shares unrecoverable; rotating it without a migration strategy can also make them inaccessible.

## 6. Optional email verification

The sender can associate an email address with a share. The recipient requests a six-digit code after opening the link; no verification email is sent when the share is created. The code is generated with a cryptographic random-number generator, expires after five minutes, and is limited to one send per minute and five sends per hour for the share and mailbox. In addition, the implementation limits code requests to ten per hour and thirty per day per effective IP. A code may be tried three times before the active challenge is removed. Failed code submissions are limited to thirty per hour and one hundred per day per IP. These event limits use keyed IP identifiers and database-backed records; the plaintext IP is recorded separately in the general secret-request audit table.

On successful verification, the recipient receives a share-bound browser session that lasts 30 minutes. It is carried in a `Secure`, `HttpOnly`, `SameSite=Strict` cookie. The code is an access gate, not an encryption key and not proof of a person's identity beyond access to that mailbox at that time. When both email verification and an access code are configured, the recipient completes email verification before unlocking the content with the access code.

The database stores a keyed verifier for the code rather than the plaintext code. Pending email jobs store the code encrypted with AES-GCM using a key derived from the separate email-verification HMAC key and a purpose label. The plaintext code is not stored in PostgreSQL. A worker delivers the email through the configured Resend integration. The code, session, and pending mail depend on database and secret configuration; if the feature is unavailable or misconfigured, email-protected share creation is rejected.

The request endpoint intentionally uses a generic response for unknown, ineligible, rate-limited, and failed-delivery cases so a caller cannot use it to determine whether an email-protected share exists. Database-backed rolling limits, the outbox lease, and cleanup keep pending email work coordinated across API instances. A worker retry after a crash can send a duplicate email containing the same code.

## 7. One-time opening, expiry, and revocation

### One-time opening

One-time opening is optional; shares remain reusable unless the sender enables it. With PostgreSQL-backed storage, after required access checks succeed the server durably and atomically marks a one-time share as consumed before returning ciphertext. Later retrieval is rejected across API instances and after a process restart. Development in-memory storage keeps this state only in the current process; it is neither shared between instances nor durable across a restart.

After the complete response is written successfully, the API deletes the encrypted blobs and metadata. If the response is interrupted after consumption, the share remains used and cannot be fetched again; leftover stored data is handled by later expiry cleanup or revocation. This can consume the one opening even if the recipient does not receive all the bytes. It does not stop the recipient from saving, copying, photographing, or sharing content already received.

### Expiry and revocation

The API accepts expiry choices of one, seven, or fourteen days and calculates the expiry time on the server. Expired content is not returned even if physical cleanup is still pending. The background cleanup defaults to running every 15 minutes and processes up to 100 expired shares per batch.

At creation, the sender receives a random 32-byte revocation token. The API stores its SHA-256 hash. Revocation first makes the share unavailable by removing its metadata, then attempts to delete its associated blobs. A filesystem error can leave encrypted blob data behind. Deletion by the application does not guarantee overwriting physical storage or removing copies from snapshots, backups, or recipient devices. Deleting a sender-history entry does not revoke a share.

## 8. Sender history

New links are saved automatically in the browser's IndexedDB database as individual AES-256-GCM encrypted records. The browser creates a non-extractable encryption key and stores it in the same database and browser profile. Each history record contains the full share link, optional access code, revocation token, and optional label. Record identifiers, version, timestamps, and nonce are outside the encrypted record; the identifier, version, timestamps, and fixed database name are authenticated as additional data.

Neither the history records nor the key are sent to the API. This protects against casual inspection of the stored record bytes; it is not a separately authenticated vault. Anyone who can use the browser profile or run code from the website origin may be able to decrypt the records while the application is available. If browser site data or the key is lost, the history cannot be recovered. Expired entries are cleaned up by the browser while the application is active. Clearing history does not revoke the corresponding server-side shares.

## 9. Request audit, logging, and privacy

The repository's application audit middleware records HTTP requests concerning shares, including failures and rejected requests. The persistent audit record contains request and trace identifiers, share identifier, action and route category, start and completion times, duration, outcome, HTTP status and a controlled error code, and the effective client IP. Requests for files may include a file identifier. The IP is stored in readable form. The audit table does not have a time-based deletion path in the repository; the operating documentation describes records as retained without a time limit, including after the share is deleted.

These records form a lasting history of requests and IP addresses. They are personal data and should not be described as anonymous. They are available through the authenticated administrative interface and to authorized database operators; there is no public audit endpoint. General application audit logs are separate and record operation metadata, status, trace ID and duration, plus a truncated HMAC of the client IP when configured. The application is designed not to log request bodies, client keys, passwords, or message content. This does not establish what a reverse proxy, cloud platform, host, database operator, email provider, or monitoring service may log.

The audit writer uses PostgreSQL in the configured database-backed installation. If the initial audit insert fails, the request is rejected before the share action proceeds. Without PostgreSQL, development uses temporary in-memory audit storage. Whether a live service uses the same database, retention, or access controls is unverified. The service owner should align its public privacy notice with the actual deployed data, purposes, recipients, access controls, and retention policy.

## 10. Request protections and operating defaults

The values below are repository defaults and may be changed by configuration. Rate limits based on the API's in-memory limiter are per process. Email verification event limits use PostgreSQL-backed shared records. Effective client IP handling depends on configuring exact trusted proxy addresses; arbitrary forwarding headers are not trusted.

| Operation or resource | Default in this repository |
| --- | --- |
| Share creation | 20 per IP per hour and 100 per IP per day |
| Create-proof challenge requests | 40 per IP per hour and 400 per IP per day, derived from the creation limits |
| Share opening | 30 per IP per minute |
| Open-proof challenge requests | 60 per IP per minute |
| Access-code unlock | 5 per IP per minute and 20 per IP per hour, plus the separate per-share failed-attempt limit described above |
| Revocation | 5 per IP per minute and 20 per IP per hour |
| Admin login | 5 attempts per IP per 15 minutes; successful admin cookies last eight hours without sliding renewal |
| Email-code request | 10 requests per IP per hour and 30 per IP per day; also one email per share and mailbox per minute, up to 5 per hour |
| Failed email-code submissions | 30 per IP per hour and 100 per IP per day; each active code can be tried 3 times |
| Message | 20,000 Unicode code points in the browser and 80,000 UTF-8 bytes enforced at the API |
| Files | Up to 15 files and 75 MiB total declared plaintext file size; file extensions use a configurable allowlist |
| Create request body | 110 MiB |
| Stored shares | 10,000 active shares and 256 MiB of ciphertext by default in the database-backed store |

Message code-point count is a browser-side check; the API enforces the byte limit. For files, the API checks that ciphertext length matches the declared plaintext size after accounting for the 16-byte GCM tag, checks allowed extensions and size bounds, but cannot inspect file signatures or contents. MIME type is client-supplied. The total file size default and request body maximum can be configured.

### Proof of work

The browser solves a short SHA-256 puzzle for creation, opening, unlocking, and per-file retrieval. A challenge contains a random 16-byte identifier and nonce, a difficulty, an expiry time, and a 32-byte HMAC-SHA-256 signature. It expires after five minutes and can be consumed only once. The proof is a counter whose SHA-256 input must begin with the required number of zero bits. For opening, the signature and proof bind the challenge to the share and requested operation. The default difficulty is 17 leading zero bits for creation and 17 for opening; configuration permits 1 to 24 bits. The current values are baselines, not evidence of phone performance calibration.

Proof of work raises the cost of simple automated clients. It does not authenticate a user, prove a human is present, prevent request bytes from reaching the server, prevent proxy buffering, or protect against denial-of-service attacks or bots that implement the puzzle. Rate limits, validation, body-size limits, and storage limits remain necessary. The replay store accepts at most 10,000 consumed challenges per operation scope before expired entries are cleaned up. In a database-backed deployment it is shared through PostgreSQL; temporary development storage is process-local. If the store is full or unavailable, proof validation temporarily fails closed.

### Transport and browser controls

The production configuration requires HTTPS and enables HSTS by default on HTTPS responses. TLS may terminate at a reverse proxy; only explicitly configured trusted proxy addresses are accepted for forwarded scheme and client-IP information. The browser app and API are designed to use the same origin. The API sets `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, a same-origin Content Security Policy, frame protections, cross-origin policies, and a restrictive Permissions Policy. It rejects cross-origin state-changing requests based on `Origin` and `Sec-Fetch-Site` checks, with a separate browser-extension path.

These response and request controls reduce selected browser attack paths. They do not make a vulnerable browser, malicious extension, cross-site scripting flaw, compromised app origin, DNS/TLS infrastructure, or infected endpoint safe. The effective production headers and proxy behavior still require live verification.

## 11. Failure cases and their effects

| Event | Expected effect in the application |
| --- | --- |
| Wrong share key or changed encrypted bytes | Browser decryption/authentication fails; the application cannot recover the original content from the damaged data. |
| Invalid or unsupported protocol version | The client rejects it rather than silently interpreting it as version 1. |
| Wrong access code | The outer authenticated decryption fails. Attempt counters may eventually place that share in a cooldown. |
| Argon2 capacity full or queued unlock times out | Unlock is temporarily rejected; a response includes a retry delay where available. A started KDF may continue after client disconnect. |
| Missing/invalid proof or expired challenge | The request is rejected; the browser needs a fresh challenge. Replayed proofs are rejected. |
| Email provider refuses, times out, or cannot confirm send | The generic code-request response remains the same; the challenge is invalidated by the delivery flow and the recipient may request another code after the per-share cooldown. |
| Email code expires or reaches failed-attempt limit | Verification does not create an access session; the recipient needs a new code. |
| One-time response is interrupted after consumption | The share remains consumed; the recipient may not retrieve it again, even if the response was incomplete. |
| Blob deletion fails on revoke, expiry, or one-time cleanup | The share can be inaccessible while encrypted bytes remain in storage. Backups and snapshots have separate retention. |
| Audit storage unavailable | In a database-backed application, a secret request is rejected if its audit record cannot be started. The audit outcome is normally recorded before the buffered response is released. For one-time opening, completion is recorded after the response is written so cleanup can follow delivery; an audit-finalization failure at that point cannot retract content already sent. |
| Browser history key or site data is lost | Locally stored history may be unrecoverable; server shares are unaffected unless separately revoked or expired. |

## 12. Verification and maintenance

The repository contains automated client-cryptography, API, persistence, and integration tests. They cover defined paths under test conditions. They do not prove that all attacks have been considered, that a live service runs this code, or that external providers and infrastructure are configured as expected. No independent cryptographic or security assessment is claimed here.

This paper is maintained as Markdown alongside the application. Changes to cryptographic formats, access controls, metadata, audit behavior, limits, default configuration, data retention, or failure handling should update this document in the same change. If a relevant change does not alter the paper, that decision should be stated in the change review. This describes repository behavior; live deployments require separate checks of release identity, effective settings, network boundaries, logs, storage, backups, and access controls.
