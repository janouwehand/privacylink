import { AfterViewInit, Component, inject } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { AppState } from '../app-state';
import { LanguageState } from '../language-state';
import { HistoryState } from './history-state';

@Component({
  selector: 'app-history-page',
  imports: [DatePipe, RouterLink],
  templateUrl: './history-page.html'
})
export class HistoryPage implements AfterViewInit {
  protected readonly app = inject(AppState);
  protected readonly history = inject(HistoryState);
  protected readonly language = inject(LanguageState);

  constructor() { this.app.activatePage('history'); }

  ngAfterViewInit(): void { document.getElementById('page-title')?.focus(); }
}
