import { DOCUMENT } from '@angular/common';
import { inject, Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class LinkSharingState {
  readonly canShare = typeof navigator.share === 'function';

  private readonly document = inject(DOCUMENT);

  async copy(value: string): Promise<boolean> {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch {
      return false;
    }
  }

  async share(url: string): Promise<void> {
    try { await navigator.share({ url }); } catch { /* The user may cancel the native share sheet. */ }
  }

  openInNewTab(value: string): void {
    try {
      const url = new URL(value);
      if (url.protocol === 'http:' || url.protocol === 'https:') {
        this.document.defaultView?.open(url.href, '_blank', 'noopener,noreferrer');
      }
    } catch { /* Ignore invalid or unsupported links in browser history. */ }
  }
}
