import { AfterViewInit, Component, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { AppState } from '../app-state';
import { LanguageState } from '../language-state';

type AdminAuditRecord = {
  id: number;
  traceId: string;
  secretId: string;
  secretIdSource: string;
  requestedSecretId: string | null;
  action: string;
  httpMethod: string;
  routeTemplate: string;
  startedAt: string;
  completedAt: string | null;
  durationMs: number | null;
  state: string;
  outcome: string | null;
  httpStatus: number | null;
  errorCode: string | null;
  clientIp: string | null;
  fileId: string | null;
};

type AdminAuditPage = { items: AdminAuditRecord[]; nextBeforeId: number | null };

@Component({
  selector: 'app-admin-page',
  imports: [DatePipe],
  templateUrl: './admin-page.html'
})
export class AdminPage implements AfterViewInit {
  protected readonly app = inject(AppState);
  protected readonly language = inject(LanguageState);
  protected readonly authenticated = signal(false);
  protected readonly checkingSession = signal(true);
  protected readonly password = signal('');
  protected readonly busy = signal(false);
  protected readonly loading = signal(false);
  protected readonly error = signal('');
  protected readonly records = signal<AdminAuditRecord[]>([]);
  protected readonly nextBeforeId = signal<number | null>(null);

  constructor() {
    this.app.activatePage('admin');
    void this.checkSession();
  }

  ngAfterViewInit(): void { document.getElementById('page-title')?.focus(); }

  async login(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set('');
    try {
      const response = await fetch('/api/v1/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: this.password() }),
        cache: 'no-store',
        referrerPolicy: 'no-referrer'
      });
      this.password.set('');
      if (!response.ok) {
        this.error.set(this.language.t('adminLoginFailed'));
        return;
      }
      this.authenticated.set(true);
      await this.loadLatest();
    } catch {
      this.error.set(this.language.t('adminLoginFailed'));
    } finally {
      this.busy.set(false);
    }
  }

  async logout(): Promise<void> {
    try {
      await fetch('/api/v1/admin/logout', { method: 'POST', cache: 'no-store', referrerPolicy: 'no-referrer' });
    } finally {
      this.authenticated.set(false);
      this.records.set([]);
      this.nextBeforeId.set(null);
    }
  }

  async refresh(): Promise<void> { await this.loadLatest(); }

  async loadOlder(): Promise<void> {
    const beforeId = this.nextBeforeId();
    if (beforeId === null || this.loading()) return;
    await this.loadPage(beforeId, true);
  }

  private async checkSession(): Promise<void> {
    try {
      const response = await fetch('/api/v1/admin/session', { cache: 'no-store', referrerPolicy: 'no-referrer' });
      if (response.ok) {
        this.authenticated.set(true);
        await this.loadLatest();
      }
    } catch {
      this.error.set(this.language.t('adminLoadFailed'));
    } finally {
      this.checkingSession.set(false);
    }
  }

  private async loadLatest(): Promise<void> {
    this.records.set([]);
    this.nextBeforeId.set(null);
    await this.loadPage(null, false);
  }

  private async loadPage(beforeId: number | null, append: boolean): Promise<void> {
    this.loading.set(true);
    this.error.set('');
    try {
      const query = beforeId === null ? '' : `?beforeId=${encodeURIComponent(beforeId)}`;
      const response = await fetch(`/api/v1/admin/audit${query}`, { cache: 'no-store', referrerPolicy: 'no-referrer' });
      if (response.status === 401) {
        this.authenticated.set(false);
        this.records.set([]);
        return;
      }
      if (!response.ok) throw new Error('Audit request failed.');
      const page = await response.json() as AdminAuditPage;
      this.records.set(append ? [...this.records(), ...page.items] : page.items);
      this.nextBeforeId.set(page.nextBeforeId);
    } catch {
      this.error.set(this.language.t('adminLoadFailed'));
    } finally {
      this.loading.set(false);
    }
  }
}
