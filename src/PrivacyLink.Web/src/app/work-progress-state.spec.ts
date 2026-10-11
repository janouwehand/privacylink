import { afterEach, describe, expect, it, vi } from 'vitest';
import { WorkProgressState } from './work-progress-state';

describe('WorkProgressState', () => {
  afterEach(() => vi.useRealTimers());

  it('shows delayed work and exposes per-file status updates', () => {
    vi.useFakeTimers();
    const progress = new WorkProgressState();

    progress.begin('create', ['report.pdf', 'photo.png']);
    expect(progress.visible()).toBe(false);
    vi.advanceTimersByTime(120);
    expect(progress.visible()).toBe(true);

    progress.setFileStatus(0, 'processing');
    progress.setFileStatus(1, 'done');
    expect(progress.files()).toEqual([
      { name: 'report.pdf', status: 'processing' },
      { name: 'photo.png', status: 'done' }
    ]);
    progress.finish();
    expect(progress.visible()).toBe(false);
    expect(progress.files()).toEqual([]);
  });

  it('does not flash the modal when work finishes quickly', () => {
    vi.useFakeTimers();
    const progress = new WorkProgressState();

    progress.begin('download', ['report.pdf']);
    progress.finish();
    vi.advanceTimersByTime(120);

    expect(progress.visible()).toBe(false);
  });
});
