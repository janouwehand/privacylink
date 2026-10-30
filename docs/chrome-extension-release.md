# Chrome extension release configuration

The extension release workflow accepts version tags in the form `extension-vMAJOR.MINOR.PATCH`, with an optional fourth numeric version component. The tag version must match `manifest.json`. The workflow builds the package, verifies the local Manifest V3 bundle and permissions, creates a ZIP artifact, and attaches GitHub build provenance to that exact archive. The artifact and its SHA-256 checksum remain available in the workflow run.

## Protected release environment

Before the first release, create a GitHub Actions environment named `chrome-web-store-release` and configure all of these environment protections:

- Require approval from designated reviewers; enable prevention of self-review where available.
- Restrict deployment branches and tags to the intended `extension-v*` release tags.
- Store the release credentials below as environment secrets only. Do not create repository or organization copies of them.

The credentialed job has a job-level check for a tag ref starting with `refs/tags/extension-v` and does not request the protected environment until that condition passes. GitHub environment approval happens before the job can read its environment secrets. Configure the environment rules in repository settings; workflow YAML cannot create or verify those repository settings.

## Environment secrets

- `VERIFIED_CRX_PRIVATE_KEY`: PEM-encoded RSA private key matching the public key enrolled for Verified CRX uploads.
- `CWS_EXTENSION_ID`: final Chrome Web Store item ID.
- `CWS_PUBLISHER_ID`: publisher ID shown in the Chrome Web Store Developer Dashboard.
- `CWS_OAUTH_CLIENT_ID`, `CWS_OAUTH_CLIENT_SECRET`, and `CWS_OAUTH_REFRESH_TOKEN`: OAuth credentials authorized for the Chrome Web Store API.

The final Store ID and matching public key are unknown. Do not populate guessed values. Create the Store item and listing manually, enroll the matching RSA public key for Verified CRX uploads, then add the final values and API credentials to the protected environment. This configuration does not set production `Security__ChromeExtensionOrigin`; leave that unset until the final Store ID is known.

## Release status

The workflow signs the verified package with Chrome's CRX packager, uploads that signed package using the Chrome Web Store API, and separately submits it for review. A successful upload is not publication. A successful submission means only that the Store accepted the review request; the Store's review and live status must be checked separately in the Developer Dashboard.

No Store upload or publication is performed while validating this workflow. Build, package verification, signing, upload, and submission each have separate steps so failures are attributed to the stage that failed.
