# PrivacyLink client core

This folder contains browser-platform TypeScript shared by PrivacyLink clients. It has no Angular dependency or UI state. Applications should import from `src/index.ts` and provide their own UI, API transport, worker lifecycle, and storage.

The cryptographic functions use standard browser APIs (`crypto.subtle`, `TextEncoder`, `File`, `atob`, and `btoa`) and preserve the existing PrivacyLink protocol. Keep wire-format and cryptographic behavior changes separate from code-sharing refactors.
