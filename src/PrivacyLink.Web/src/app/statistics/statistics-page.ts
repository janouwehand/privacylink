import { AfterViewInit, Component, inject } from '@angular/core';
import { AppState } from '../app-state';
import { LanguageState } from '../language-state';

@Component({
  selector: 'app-statistics-page',
  templateUrl: './statistics-page.html'
})
export class StatisticsPage implements AfterViewInit {
  protected readonly app = inject(AppState);
  protected readonly language = inject(LanguageState);

  constructor() {
    this.app.activatePage('statistics');
  }

  ngAfterViewInit(): void { document.getElementById('page-title')?.focus(); }
}
