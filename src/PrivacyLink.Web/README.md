# PrivacyLink Web

PrivacyLink Web is the Angular 22 single page application for creating and opening encrypted links. The app uses Angular Router and keeps shared shell, language, and feature state in focused injectable classes.

## Run locally

Use Node.js 24 and npm. Start the API in a separate terminal from the repository root:

```powershell
$env:ASPNETCORE_ENVIRONMENT = "Development"
dotnet run --project src/PrivacyLink.Api --urls http://localhost:5080
```

Then start the frontend from `src/PrivacyLink.Web`:

```powershell
npm ci
npm start
```

The development server runs at `http://localhost:4200`. Its proxy forwards `/api` and `/health` to the API on port 5080. See the repository [README](../../README.md) for backend configuration and the full local setup.

## Routes

| URL | Screen |
| --- | --- |
| `/` | Create a secure link and show its result |
| `/history` | View and manage links stored in this browser |
| `/security` | Explain the encryption and link protocol |
| `/stats` | Explain that statistics are temporarily unavailable |
| `/s/:id` | Check a shared link and open its content on user action |
| Other paths | Show the translated not-found screen |

The result screen is part of `/`; it does not put the client key into Angular route state. The API serves the SPA fallback for deep links. A different static host must also rewrite these application routes to `index.html`.

## Translation and link handling

Dutch and English UI copy lives in the typed catalog in `src/app/translations.ts`. Add visible text, accessible names, and page titles to both catalogs. Translation keys and interpolation parameters are type checked. The selected language is stored in browser local storage; changing it updates the page without a reload, including `html[lang]`, the document title, and locale-aware dates and numbers.

The recipient route reads the client key from the URL fragment after `#`. Fragments are not sent in HTTP requests. Keep the key out of route parameters, query parameters, API calls, and logs. The app requests metadata when a recipient route opens; encrypted content is requested only after the user presses the open or unlock button.

## Checks

```powershell
npm test
npm run build
```

The shared `tsconfig.json` enables TypeScript `strict` checks and Angular `strictTemplates`. Tests use a stubbed API and cover route screens, language switching and error translation, link creation, explicit unlock, and safe text rendering of decrypted content. For manual accessibility review, check keyboard focus after route changes, language buttons, dialogs, file selection, and the narrow-screen history layout.

## Code map

| Path | Responsibility |
| --- | --- |
| `src/app/app.ts` and `app.html` | Shared shell, navigation, and dialog host |
| `src/app/*/*-page.ts` and `*-page.html` | Route screens |
| `src/app/app-state.ts` | Current screen and localized document title |
| `src/app/language-state.ts` and `src/app/translations.ts` | Language preference, formatting, and typed Dutch/English copy |
| `src/app/create/create-state.ts` | Create form, file policy, encryption request, and result state |
| `src/app/recipient/recipient-state.ts` | Recipient metadata, explicit unlock, and decryption |
| `src/app/history/history-state.ts` | History actions, copy/share feedback, and confirmation state |
| `src/app/link-sharing-state.ts` | Browser clipboard, native sharing, and safe new-tab opening |
| `src/app/secret-api.ts` | HTTP boundary |
| `src/app/secret-history-store.ts` | Browser history persistence |
| `src/app/secret-crypto.ts` | Browser encryption and decryption |
