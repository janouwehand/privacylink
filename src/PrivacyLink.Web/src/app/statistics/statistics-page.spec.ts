import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { vi } from 'vitest';
import { LanguageState } from '../language-state';
import { DailyStatistic, StatisticsApi } from './statistics-api';
import { StatisticsPage } from './statistics-page';

describe('StatisticsPage', () => {
  it('shows daily aggregates and the unique IP total in the selected language', async () => {
    const rows: DailyStatistic[] = [
      { day: '2026-09-30', metric: 'creations', dimension: '', dimensionValue: '', count: 4, bytes: 0 },
      { day: '2026-09-30', metric: 'creation_content_type', dimension: 'content_type', dimensionValue: 'text', count: 3, bytes: 0 },
      { day: '2026-09-30', metric: 'unique_ips', dimension: '', dimensionValue: '', count: 2, bytes: 0 }
    ];
    const api = { getDailyStatistics: vi.fn().mockResolvedValue(rows) };
    await TestBed.configureTestingModule({
      imports: [StatisticsPage],
      providers: [provideRouter([]), { provide: StatisticsApi, useValue: api }]
    }).compileComponents();
    TestBed.inject(LanguageState).setLanguage('en');
    const fixture = TestBed.createComponent(StatisticsPage);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const content = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(api.getDailyStatistics).toHaveBeenCalledOnce();
    expect(content).toContain('Successful creations');
    expect(content).toContain('Creations by content type');
    expect(content).toContain('Unique IP addresses');
    expect(content).toContain('2');
    expect(content).toContain('not mean anyone read the message');
    expect(content).toContain('Password-protected files are sent during unlock');
  });

  it('renders the empty state when no daily rows are available', async () => {
    await TestBed.configureTestingModule({
      imports: [StatisticsPage],
      providers: [provideRouter([]), { provide: StatisticsApi, useValue: { getDailyStatistics: vi.fn().mockResolvedValue([]) } }]
    }).compileComponents();
    TestBed.inject(LanguageState).setLanguage('nl');
    const fixture = TestBed.createComponent(StatisticsPage);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Er zijn nog geen statistieken beschikbaar.');
  });
});
