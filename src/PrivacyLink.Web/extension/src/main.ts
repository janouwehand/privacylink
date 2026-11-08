import { provideBrowserGlobalErrorListeners } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideRouter } from '@angular/router';
import { App } from '../../src/app/app';
import { PRIVACYLINK_API_ORIGIN } from '../../src/app/secret-api';
import { CREATE_HISTORY_ENABLED, PRIVACYLINK_SHARE_ORIGIN } from '../../src/app/create/create-state';
import { CreatePage } from '../../src/app/create/create-page';
import { SecurityDetailsPage } from '../../src/app/security/security-details-page';
import { NotFoundPage } from '../../src/app/not-found/not-found-page';
import { LINK_SHARING_ADAPTER } from '../../src/app/link-sharing-state';
import { LANGUAGE_STORAGE_ADAPTER } from '../../src/app/language-state';

const extensionRoutes = [
  { path: '', component: CreatePage },
  { path: 'securitydetails', component: SecurityDetailsPage },
  { path: '**', component: NotFoundPage }
];

document.documentElement.setAttribute('data-client', 'extension');
bootstrapApplication(App, {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(extensionRoutes),
    { provide: PRIVACYLINK_API_ORIGIN, useValue: 'https://privacylink.nl' },
    { provide: PRIVACYLINK_SHARE_ORIGIN, useValue: 'https://privacylink.nl' },
    { provide: LINK_SHARING_ADAPTER, useValue: {
      copy: (value: string) => navigator.clipboard.writeText(value),
      share: async (url: string) => { if (typeof navigator.share === 'function') await navigator.share({ url }); }
    } },
    { provide: LANGUAGE_STORAGE_ADAPTER, useValue: {
      get: (key: string) => window.localStorage.getItem(key),
      set: (key: string, value: string) => window.localStorage.setItem(key, value)
    } },
    { provide: CREATE_HISTORY_ENABLED, useValue: false }
  ]
}).catch(error => console.error(error));
