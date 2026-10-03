import { AfterViewInit, Component, computed, inject, signal } from '@angular/core';
import { AppState } from '../app-state';
import { LanguageState } from '../language-state';
import { DailyStatistic, StatisticsApi } from './statistics-api';

@Component({
  selector: 'app-statistics-page',
  templateUrl: './statistics-page.html'
})
export class StatisticsPage implements AfterViewInit {
  protected readonly app = inject(AppState);
  protected readonly language = inject(LanguageState);
  protected readonly loading = signal(true);
  protected readonly failed = signal(false);
  private readonly rows = signal<DailyStatistic[]>([]);
  protected readonly totals = computed<DailyStatistic[]>(() => {
    const totals = new Map<string, DailyStatistic>();
    for (const row of this.rows()) {
      const key = `${row.metric}:${row.dimension}:${row.dimensionValue}`;
      const total = totals.get(key);
      if (total) {
        total.count += row.count;
        total.bytes += row.bytes;
      } else {
        totals.set(key, { ...row });
      }
    }
    return [...totals.values()];
  });

  constructor(private readonly api: StatisticsApi) {
    this.app.activatePage('statistics');
    void this.load();
  }

  ngAfterViewInit(): void { document.getElementById('page-title')?.focus(); }

  async load(): Promise<void> {
    this.loading.set(true);
    this.failed.set(false);
    try { this.rows.set(await this.api.getDailyStatistics()); }
    catch { this.failed.set(true); }
    finally { this.loading.set(false); }
  }

  formatBytes(bytes: number): string {
    return bytes < 1024 ? `${this.language.formatNumber(bytes)} ${this.language.t('bytes')}` : this.language.formatFileSize(bytes);
  }

  metricLabel(metric: string): string {
    const labels: Record<string, string> = {
      creations: this.language.t('statsCreations'),
      creation_content_type: this.language.t('statsCreationContentType'),
      creation_password_protected: this.language.t('statsCreationPassword'),
      creation_expiry: this.language.t('statsCreationExpiry'),
      secret_open: this.language.t('statsSecretOpen'),
      unlock: this.language.t('statsUnlock'),
      file_retrieval: this.language.t('statsFileRetrieval'),
      files: this.language.t('statsFiles'),
      errors: this.language.t('statsErrors'),
      unique_ips: this.language.t('statsUniqueIps')
    };
    return labels[metric] ?? this.language.t('statsOther');
  }

  dimensionLabel(row: DailyStatistic): string {
    if (!row.dimension) return '';
    const values: Record<string, string> = {
      text: this.language.t('statsText'),
      files: this.language.t('statsFilesOnly'),
      both: this.language.t('statsBoth'),
      true: this.language.t('statsProtected'),
      false: this.language.t('statsUnprotected'),
      '1d': this.language.t('day'),
      '7d': this.language.t('week'),
      '14d': this.language.t('twoWeeks'),
      validation: this.language.t('statsErrorValidation'),
      rate_limit: this.language.t('statsErrorRateLimit'),
      capacity: this.language.t('statsErrorCapacity'),
      server_error: this.language.t('statsErrorServer')
    };
    return values[row.dimensionValue] ?? this.language.t('statsOther');
  }
}
