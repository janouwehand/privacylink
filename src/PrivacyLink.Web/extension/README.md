# PrivacyLink Chrome extension

This package is a standalone Manifest V3 extension for creating and opening PrivacyLink secrets. The popup creates text secrets. A locally bundled, isolated content script handles only canonical share links on `https://privacylink.nl/s/*`; it validates the link, removes the fragment from the website URL before website scripts start, and renders the recipient flow inside a closed shadow root. The extension code uses the framework-independent `PrivacyLink.Client` TypeScript core for encryption and decryption.

## Build and load locally

From this directory's parent (`src/PrivacyLink.Web`), run:

```powershell
npm run build:extension
npm run verify:extension
```

In Chrome, open `chrome://extensions`, enable Developer mode, then choose **Load unpacked** and select `dist/privacy-link-extension/browser`.

All popup HTML, styles, recipient code, and executable JavaScript are included in the generated package. The manifest grants clipboard write and access to the PrivacyLink host only. Its content script matches the share-route family, runs in the isolated world and top frame, and declines any route that does not contain a canonical secret ID and fragment key. It makes same-origin API calls from the PrivacyLink page so existing email-verification cookies continue to work. The fragment key stays in the content script's memory for validation and local decryption; it is not sent to the API, stored, or passed through extension messages. If site access is not granted, Chrome does not inject the content script and the website continues handling the route.

The runtime API calls are the existing create, metadata, open, unlock, email-verification, and file-open routes on `https://privacylink.nl`. No API route or payload contract is added or changed.

## Runtime configuration

Production popup creation depends on the API setting `Security__ChromeExtensionOrigin` matching the extension origin exactly: `chrome-extension://<final-32-character-Store-ID>`. The final Chrome Web Store ID and its matching public key are not known yet, so this package contains no guessed production ID or public key. Configure the API and package with the final values when they are supplied. This work does not upload or publish the extension. Recipient handling uses same-origin website API requests and does not depend on this extension-origin setting.
