import { startRecipientContentScript } from './recipient-flow';

if (typeof document !== 'undefined' && typeof location !== 'undefined') {
  startRecipientContentScript(document, location.href);
}
