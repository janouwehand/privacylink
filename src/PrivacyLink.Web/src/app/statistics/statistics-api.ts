import { Injectable } from '@angular/core';

export interface DailyStatistic {
  day: string;
  metric: string;
  dimension: string;
  dimensionValue: string;
  count: number;
  bytes: number;
}

@Injectable({ providedIn: 'root' })
export class StatisticsApi {
  async getDailyStatistics(): Promise<DailyStatistic[]> {
    const response = await fetch('/api/v1/stats', { cache: 'no-store', referrerPolicy: 'no-referrer' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json() as Promise<DailyStatistic[]>;
  }
}
