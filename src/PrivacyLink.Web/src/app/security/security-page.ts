import { AfterViewInit, Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AppState } from '../app-state';
import { LanguageState } from '../language-state';

@Component({
  selector: 'app-security-page',
  imports: [RouterLink],
  templateUrl: './security-page.html'
})
export class SecurityPage implements AfterViewInit {
  protected readonly app = inject(AppState);
  protected readonly language = inject(LanguageState);

  constructor() { this.app.activatePage('security'); }

  ngAfterViewInit(): void { document.getElementById('page-title')?.focus(); }
}
