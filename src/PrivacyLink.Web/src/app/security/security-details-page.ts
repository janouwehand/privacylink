import { AfterViewInit, Component, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { AppState } from '../app-state';
import { LanguageState } from '../language-state';

const content = {
  nl: {
    eyebrow: 'Technische toelichting',
    title: 'PrivacyLink-beveiligingswhitepaper',
    intro: 'Deze Engelstalige whitepaper beschrijft de code in deze repository. De instellingen en softwareversie van een live dienst zijn niet gecontroleerd; dit is geen onafhankelijke beveiligingsbeoordeling.',
    loading: 'Whitepaper laden…',
    loaded: 'Whitepaper geladen.',
    unavailable: 'De whitepaper kon niet worden geladen. Probeer het later opnieuw.',
    back: 'Terug naar de beveiligingsuitleg'
  },
  en: {
    eyebrow: 'Technical overview',
    title: 'PrivacyLink Security Whitepaper',
    intro: 'This English-language whitepaper describes the code in this repository. The settings and software version of a live service have not been checked; this is not an independent security assessment.',
    loading: 'Loading the whitepaper…',
    loaded: 'Whitepaper loaded.',
    unavailable: 'The whitepaper could not be loaded. Please try again later.',
    back: 'Back to the security explanation'
  }
} as const;

@Component({
  selector: 'app-security-details-page',
  imports: [RouterLink],
  templateUrl: './security-details-page.html'
})
export class SecurityDetailsPage implements AfterViewInit {
  protected readonly app = inject(AppState);
  protected readonly language = inject(LanguageState);
  protected readonly content = content;
  protected readonly whitepaperHtml = signal('');
  protected readonly whitepaperUnavailable = signal(false);

  constructor() {
    this.app.activatePage('security-details');
    void fetch('/security/security-whitepaper.html', { cache: 'no-cache' })
      .then((response) => {
        if (!response.ok) throw new Error('Whitepaper request failed');
        return response.text();
      })
      .then((html) => this.whitepaperHtml.set(html))
      .catch(() => this.whitepaperUnavailable.set(true));
  }

  ngAfterViewInit(): void { document.getElementById('page-title')?.focus(); }
}
