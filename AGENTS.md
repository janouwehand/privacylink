## Agent skills

### Language

Use English for new issues, specifications, project documentation, and communication by default, unless the user explicitly asks for another language. Existing documents may remain in their original language unless they need revision.

### Issue tracker

Issues and specifications for this repository live in GitHub Issues. Pull requests are not a request intake surface. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the five standard triage labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, and `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repository. Read the root `CONTEXT.md` and relevant ADRs under `docs/adr/` when they exist. See `docs/agents/domain.md`.

### Security whitepaper

Keep `docs/security-whitepaper.md` accurate and in sync with relevant changes to the application, its security model, protocol, defaults, and data handling. When making such changes, review and update the whitepaper in the same change, or explicitly explain why no update is needed. Distinguish source-code behavior and defaults from production settings that have not been verified. The Markdown file is the source for the website's technical documentation.
