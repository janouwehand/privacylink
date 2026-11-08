import { DOCUMENT } from '@angular/common';
import { inject, Injectable, InjectionToken } from '@angular/core';

export interface LinkSharingAdapter {
  copy(value: string): Promise<void>;
  share(url: string): Promise<void>;
}

export const LINK_SHARING_ADAPTER = new InjectionToken<LinkSharingAdapter>('LINK_SHARING_ADAPTER', {
  providedIn: 'root',
  factory: () => ({
    copy: value => navigator.clipboard.writeText(value),
    share: async url => { if (typeof navigator.share === 'function') await navigator.share({ url }); }
  })
});

@Injectable({ providedIn: 'root' })
export class LinkSharingState {
  readonly canShare = typeof navigator.share === 'function';

  private readonly document = inject(DOCUMENT);
  private readonly adapter = inject(LINK_SHARING_ADAPTER);

  async copy(value: string): Promise<boolean> {
    try {
      await this.adapter.copy(value);
      return true;
    } catch {
      return false;
    }
  }

  async share(url: string): Promise<void> {
    try { await this.adapter.share(url); } catch { /* The user may cancel the native share sheet. */ }
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
