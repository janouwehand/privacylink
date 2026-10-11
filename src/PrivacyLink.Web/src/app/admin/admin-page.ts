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

type AdminAuditPage = { items: AdminAuditRecord[]; page: number; pageSize: number; totalCount: number };
type AuditSort = 'time' | 'action' | 'secretId' | 'clientIp' | 'outcome' | 'httpStatus' | 'request';

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
  protected readonly page = signal(1);
  protected readonly pageSize = signal(25);
  protected readonly totalCount = signal(0);
  protected readonly sortBy = signal<AuditSort>('time');
  protected readonly sortDescending = signal(true);
  protected readonly secretIdInput = signal('');
  protected readonly clientIpInput = signal('');
  protected readonly secretIdFilter = signal('');
  protected readonly clientIpFilter = signal('');
  private loadVersion = 0;

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
      await this.loadPage(1);
    } catch {
      this.error.set(this.language.t('adminLoginFailed'));
    } finally {
      this.busy.set(false);
    }
  }

  async logout(): Promise<void> {
    this.loadVersion++;
    this.loading.set(false);
    try {
      await fetch('/api/v1/admin/logout', { method: 'POST', cache: 'no-store', referrerPolicy: 'no-referrer' });
    } finally {
      this.authenticated.set(false);
      this.records.set([]);
      this.totalCount.set(0);
      this.page.set(1);
    }
  }

  async refresh(): Promise<void> { await this.loadPage(this.page()); }

  async applyFilters(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    this.secretIdFilter.set(this.secretIdInput().trim());
    this.clientIpFilter.set(this.clientIpInput().trim());
    await this.loadPage(1);
  }

  async setSort(column: AuditSort): Promise<void> {
    if (this.sortBy() === column) this.sortDescending.set(!this.sortDescending());
    else {
      this.sortBy.set(column);
      this.sortDescending.set(column === 'time');
    }
    await this.loadPage(1);
  }

  async setPageSize(event: Event): Promise<void> {
    this.pageSize.set(Number((event.target as HTMLSelectElement).value));
    await this.loadPage(1);
  }

  async previousPage(): Promise<void> { if (this.page() > 1) await this.loadPage(this.page() - 1); }
  async nextPage(): Promise<void> { if (this.page() < this.pageCount()) await this.loadPage(this.page() + 1); }
  protected pageCount(): number { return Math.max(1, Math.ceil(this.totalCount() / this.pageSize())); }
  protected sortIndicator(column: AuditSort): string { return this.sortBy() === column ? (this.sortDescending() ? ' ▼' : ' ▲') : ''; }
  protected sortAria(column: AuditSort): 'ascending' | 'descending' | 'none' {
    return this.sortBy() === column ? (this.sortDescending() ? 'descending' : 'ascending') : 'none';
  }
  protected sortLabel(column: string): string {
    return this.language.t('adminSortBy', { column, direction: this.sortDescending() ? this.language.t('adminDescending') : this.language.t('adminAscending') });
  }

  private async checkSession(): Promise<void> {
    try {
      const response = await fetch('/api/v1/admin/session', { cache: 'no-store', referrerPolicy: 'no-referrer' });
      if (response.ok) {
        this.authenticated.set(true);
        await this.loadPage(1);
      }
    } catch {
      this.error.set(this.language.t('adminLoadFailed'));
    } finally {
      this.checkingSession.set(false);
    }
  }

  private async loadPage(pageNumber: number): Promise<void> {
    const version = ++this.loadVersion;
    this.page.set(pageNumber);
    this.loading.set(true);
    this.error.set('');
    try {
      const params = new URLSearchParams({
        page: String(pageNumber), pageSize: String(this.pageSize()), sortBy: this.sortBy(),
        sortDirection: this.sortDescending() ? 'desc' : 'asc'
      });
      if (this.secretIdFilter()) params.set('secretId', this.secretIdFilter());
      if (this.clientIpFilter()) params.set('clientIp', this.clientIpFilter());
      const response = await fetch(`/api/v1/admin/audit?${params}`, { cache: 'no-store', referrerPolicy: 'no-referrer' });
      if (response.status === 401) {
        if (version !== this.loadVersion) return;
        this.authenticated.set(false);
        this.records.set([]);
        this.totalCount.set(0);
        return;
      }
      if (response.status === 400 && this.clientIpFilter()) throw new Error('invalid-ip');
      if (!response.ok) throw new Error('Audit request failed.');
      const page = await response.json() as AdminAuditPage;
      if (version !== this.loadVersion) return;
      const maxPage = Math.max(1, Math.ceil(page.totalCount / this.pageSize()));
      if (pageNumber > maxPage) {
        await this.loadPage(maxPage);
        return;
      }
      this.records.set(page.items);
      this.totalCount.set(page.totalCount);
      this.page.set(pageNumber);
    } catch (error) {
      if (version === this.loadVersion) this.error.set(this.language.t(error instanceof Error && error.message === 'invalid-ip' ? 'adminInvalidIp' : 'adminLoadFailed'));
    } finally {
      if (version === this.loadVersion) this.loading.set(false);
    }
  }
}
