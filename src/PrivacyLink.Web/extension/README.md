# PrivacyLink Chrome extension

This package is a standalone Manifest V3 popup for creating text secrets. It imports the framework-independent `PrivacyLink.Client` TypeScript core for encryption and signed create-challenge proof solving. Angular services, website state, and content scripts are not included.

## Build and load locally

From this directory's parent (`src/PrivacyLink.Web`), run:

```powershell
npm run build:extension
npm run verify:extension
```

In Chrome, open `chrome://extensions`, enable Developer mode, then choose **Load unpacked** and select `dist/privacy-link-extension/browser`.

All popup HTML, styles, and executable JavaScript are included in the generated package. The only network calls are the existing create-challenge and secret-create API requests to `https://privacylink.nl`.

## API integration limitation

The current API rejects cross-origin POST requests before create-proof validation. A popup-origin POST from `chrome-extension://…` to `https://privacylink.nl` is cross-site and receives `403 forbidden` under the existing middleware in `PrivacyLink.Api/Program.cs`. This extension surfaces that rejection and preserves the text in the form; it does not report a successful create. Supporting production creation needs a separately scoped server decision to accept the packaged extension origin or another narrowly defined same-origin integration. No server or protocol changes are included here.
