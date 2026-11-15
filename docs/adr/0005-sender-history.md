# ADR 0005: Encrypted browser-local sender history

- Status: Adopted (retrospective reconstruction)
- Record date: 2026-11-15

## Decision

Save newly created shares to sender history automatically in the web application. Store each history entry as an AES-256-GCM encrypted record in IndexedDB. The entry contains the full share link, access password when configured, revoke token, and optional label. The entry ID, format version, creation and expiry timestamps, and GCM IV are stored outside the ciphertext; the ID, version, timestamps, and fixed database name are authenticated as additional data. Generate a non-extractable AES-256-GCM key in the browser and store it in the same IndexedDB database. Remove expired entries through browser-side cleanup when the app is active.

The key and history remain in that browser profile and are not sent to the API. This is convenience storage, not a separately authenticated vault.

## Context and consequences

Encrypting history at rest protects the contents from casual inspection of IndexedDB records and helps avoid plaintext share credentials in browser storage. Keeping the key in the same browser database means a person or script with access to the browser profile and origin can still use the key to decrypt the entries. Same-origin malicious JavaScript can access history while the app runs. Clearing or losing browser data can make history unrecoverable; removing a history row does not revoke the corresponding server secret.

Repository history shows an earlier opt-in/passphrase design (commit `af901294`) followed by the current automatic IndexedDB design (commit `8da360be`). This ADR records the current automatic, browser-keyed design; it does not assert the original rationale for moving away from the earlier design.

## Evidence

- [History storage and encryption](../../src/PrivacyLink.Web/src/app/secret-history-store.ts)
- [Default-enabled history behavior test](../../src/PrivacyLink.Web/src/app/secret-history-store.spec.ts)
- [History save integration](../../src/PrivacyLink.Web/src/app/create/create-state.ts)
- [Security details presented by the app](../../src/PrivacyLink.Web/src/app/security/security-details-page.ts)
