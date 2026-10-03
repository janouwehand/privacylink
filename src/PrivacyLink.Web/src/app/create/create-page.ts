import { AfterViewInit, Component, inject } from '@angular/core';
import { DatePipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { AppState } from '../app-state';
import { LanguageState } from '../language-state';
import { CreateState } from './create-state';

@Component({
  selector: 'app-create-page',
  imports: [DatePipe, RouterLink],
  templateUrl: './create-page.html'
})
export class CreatePage implements AfterViewInit {
  protected readonly app = inject(AppState);
  protected readonly create = inject(CreateState);
  protected readonly language = inject(LanguageState);

  constructor() {
    this.app.activatePage('create');
    this.create.initialize();
  }

  ngAfterViewInit(): void {
    if (this.app.mode() === 'create') document.getElementById('message')?.focus();
  }
}
