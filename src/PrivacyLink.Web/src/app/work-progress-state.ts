import { Injectable, signal } from '@angular/core';

export type WorkKind = 'create' | 'open' | 'download';
export type WorkStage = 'processing' | 'uploading' | 'fetching' | 'preparing';
export type WorkFileStatus = 'pending' | 'processing' | 'done';

export interface WorkFile {
  name: string;
  status: WorkFileStatus;
}

@Injectable({ providedIn: 'root' })
export class WorkProgressState {
  readonly visible = signal(false);
  readonly active = signal(false);
  readonly kind = signal<WorkKind>('create');
  readonly stage = signal<WorkStage>('processing');
  readonly files = signal<WorkFile[]>([]);
  private showTimer: ReturnType<typeof setTimeout> | undefined;

  begin(kind: WorkKind, files: string[] = []): void {
    this.finish();
    this.active.set(true);
    this.kind.set(kind);
    this.stage.set(kind === 'download' ? 'fetching' : 'processing');
    this.files.set(files.map(name => ({ name, status: 'pending' })));
    this.showTimer = setTimeout(() => {
      this.showTimer = undefined;
      if (this.active()) this.visible.set(true);
    }, 120);
  }

  setStage(stage: WorkStage): void { if (this.active()) this.stage.set(stage); }

  setFiles(names: string[]): void {
    if (this.active()) this.files.set(names.map(name => ({ name, status: 'pending' })));
  }

  setFileName(index: number, name: string): void {
    this.files.update(files => files.map((file, fileIndex) => fileIndex === index ? { ...file, name } : file));
  }

  setFileStatus(index: number, status: WorkFileStatus): void {
    this.files.update(files => files.map((file, fileIndex) => fileIndex === index ? { ...file, status } : file));
  }

  finish(): void {
    if (this.showTimer !== undefined) clearTimeout(this.showTimer);
    this.showTimer = undefined;
    this.active.set(false);
    this.visible.set(false);
    this.files.set([]);
  }
}
