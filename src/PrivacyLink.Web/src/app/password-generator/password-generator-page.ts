import { AfterViewInit, Component, inject } from '@angular/core';
import { AppState } from '../app-state';
import { LanguageState } from '../language-state';
import { PasswordGenerator } from './password-generator';

@Component({
  selector: 'app-password-generator-page',
  imports: [PasswordGenerator],
  templateUrl: './password-generator-page.html'
})
export class PasswordGeneratorPage implements AfterViewInit {
  protected readonly app = inject(AppState);
  protected readonly language = inject(LanguageState);

  constructor() { this.app.activatePage('password-generator'); }

  ngAfterViewInit(): void { document.getElementById('page-title')?.focus(); }
}
