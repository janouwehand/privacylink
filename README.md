# PrivacyLink

PrivacyLink is a privacy-focused tool for sharing a message or files through a link without creating an account. The project aims to make this useful for the public at no cost, for reasonable or occasional use.

The browser encrypts message and file contents before sending them to the service. The link contains the key needed to open them, so anyone with the complete link may be able to read the contents. Senders can add an access code, email verification, or one-time opening. These options limit access in different ways; they cannot stop a recipient from saving or sharing content after it has been opened.

## What PrivacyLink is for

PrivacyLink is intended for sharing information that benefits from an extra privacy layer in transit and storage. It is not an anonymous service, a long-term file store, a backup system, or a guarantee that a recipient will keep information confidential. The project is designed for reasonable or occasional use rather than bulk hosting or distribution. This describes the project's intent, not a claim that a particular public installation is currently available or an enforceable service policy.

The browser keeps the content key in the link fragment, which normal HTTP requests do not send to the server. The server still processes operational metadata. This can include the expiry date, file count and file properties, and an email address when email verification is enabled. The website also stores sender history encrypted in the browser profile. Anyone who can use that profile or run code from the website may be able to access the history.

PrivacyLink does not protect a compromised device, browser, or website origin. Recipients can keep copies after opening. Expiry, revocation, and one-time opening cannot retrieve content that has already been received. Keep these limits in mind when deciding what to share. The app's “How the security works” page explains the design in plain language; the [security whitepaper](docs/security-whitepaper.md) covers implementation details and evidence limits.

## Project status and trust

This repository describes source code and checked-in configuration. That evidence does not establish the current settings, logging, release identity, or availability of any live service. The security whitepaper labels source-based findings and items that require production verification. No independent security assessment is represented by this repository unless a specific published report says otherwise.

The code is published for inspection and transparency. Copyright © 2026 Softable. All rights reserved; no license granting reuse is provided. Source visibility should not be read as permission to reuse or redistribute the code.

## For contributors and self-hosters

The project contains an Angular browser client and a .NET API. It can run locally with temporary in-memory storage or be configured with PostgreSQL and filesystem blob storage. The deployment and development guide contains prerequisites, local setup, Docker Compose, operational configuration, and verification commands:

- [Development and self-hosting guide](docs/development-and-self-hosting.md)
- [Operations runbook](docs/runbook.md)
- [Security whitepaper source](docs/security-whitepaper.md) (draft)

The current implementation is organized as follows:

| Path | Purpose |
| --- | --- |
| `src/PrivacyLink.Web` | Browser application and user interface |
| `src/PrivacyLink.Client` | Shared browser cryptography and protocol types |
| `src/PrivacyLink.Api` | HTTP API and request validation |
| `src/PrivacyLink.Services` | Application use cases and storage contracts |
| `src/PrivacyLink.Infrastructure` | PostgreSQL, blob storage, and supporting services |
| `tests` | Automated API and integration checks |
