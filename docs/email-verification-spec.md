# Spec: mailboxverificatie met eenmalige code

## Doel en scope

Voeg aan de backend een optionele mailboxverificatie toe voor een secret. De verzender stelt het adres in; de ontvanger vraagt bij het openen van de link een eenmalige code aan en voert die in voordat de API inhoud of bestanden vrijgeeft.

Mailboxverificatie is een aparte laag naast de bestaande client-side encryptiesleutel in het URL-fragment en de optionele PIN/wachtwoordlaag. Als e-mailverificatie en PIN/wachtwoord allebei zijn ingeschakeld, doorloopt de ontvanger eerst OTP, daarna PIN/wachtwoord. De browser ontsleutelt de inhoud met de sleutel uit het fragment; die sleutel wordt niet naar de API gestuurd.

Deze spec gaat over de backend. Het bestaande frontendvoorbeeld wordt later op de API aangesloten; het UI-ontwerp valt buiten scope. Alleen Resend wordt geïmplementeerd. Er komt geen providerselector, fallbackprovider of generiek mailplatform.

## Afgesproken gedrag

### Aanmaken en code aanvragen

- De verzender kan één e-mailadres instellen en dit combineren met een PIN/wachtwoord. Het adres wordt server-side gevalideerd en genormaliseerd.
- Bij het aanmaken wordt geen e-mail verstuurd. De ontvanger initieert de verzending.
- De ontvanger ziet alleen het gemaskeerde, vooraf ingestelde adres en kan dit niet wijzigen. De API haalt het volledige adres zelf uit de opgeslagen secret.
- Zonder PostgreSQL kan de app gewone secrets blijven verwerken, maar wordt het aanmaken van e-mailbeveiligde secrets geweigerd. PostgreSQL is nodig voor blijvende opslag en gedeelde limieten.
- Als Resend niet is geconfigureerd, blijft de app starten en blijven gewone secrets werken; het aanmaken van e-mailbeveiligde secrets wordt geweigerd.
- Een OTP bestaat uit zes willekeurige cijfers en is vijf minuten geldig. Na drie verkeerde invoeren vervalt de code.
- Een toegestane nieuwe aanvraag vervangt de vorige code meteen en begint een nieuwe termijn van vijf minuten. Een aanvraag die door een limiet wordt geweigerd, vervangt de bestaande code niet.
- Een correcte code kan één keer worden gebruikt en geeft een vaste verificatiesessie van 30 minuten. Activiteit verlengt die termijn niet.
- De sessie overleeft vernieuwen en nieuwe tabs in dezelfde browser. Een andere browser of apparaat moet opnieuw verifiëren.
- Als e-mailverificatie en PIN/wachtwoord beide aanstaan, moet OTP eerst worden afgerond. Daarna blijft de bestaande PIN-/wachtwoordcontrole vereist.

### Rate limits

Alle uur- en daglimieten gebruiken rollende vensters. Iedere verzendaanvraag telt mee, ook als de mail niet kan worden verstuurd.

| Limiet | Grens |
| --- | ---: |
| Tussen OTP-aanvragen per secret/e-mailadres | 60 seconden |
| OTP-verzendingen per secret/e-mailadres | 5 per 60 minuten |
| OTP-aanvragen per IP | 10 per 60 minuten; 30 per 24 uur |
| Mislukte OTP-invoeren per IP | 30 per 60 minuten; 100 per 24 uur |
| Verkeerde invoeren per code | 3 |

IP-limieten gebruiken alleen een door de server betrouwbaar vastgesteld IP-adres. Forwarded headers zijn alleen betrouwbaar wanneer ze van een expliciet vertrouwde proxy komen. De limieten moeten tussen API-instanties gedeeld zijn. OTP-aanvragen voor onbekende, verlopen of niet voor e-mail ingestelde secrets tellen ook mee voor de IP-limieten; de API gebruikt daarvoor dezelfde generieke aanvraagrespons.

### Privacy, fouten en retentie

- Een codeaanvraag geeft geen informatie over het bestaan, de status of de e-mailinstelling van een secret. Ook fouten bij mailverzending tonen geen providerdetails. De UI kan wel melden dat een code onjuist of verlopen is.
- Een fout tijdens verzending maakt de nieuwe code ongeldig; de ontvanger krijgt een algemene tijdelijke fout zonder providerdetails.
- Verstuur geen secretinhoud, client-key, PIN/wachtwoord of volledige deel-link per e-mail. Log geen OTP of mailinhoud.
- Het e-mailadres en verificatiegegevens blijven alleen bestaan zolang de secret geldig is. Bij intrekken of verlopen worden ze verwijderd en direct onbruikbaar.
- Gebruikte OTP’s worden meteen verwijderd. Een verlopen OTP is na vijf minuten ongeldig; de bestaande opruimtaak mag het record uiterlijk binnen 15 minuten fysiek verwijderen.

## Technische richting

- Volg de bestaande lagen: HTTP-contracten en afdwinging in `PrivacyLink.Api`, use cases en interfaces in `PrivacyLink.Services`, PostgreSQL en Resend-adapter in `PrivacyLink.Infrastructure`, gedeelde API-modellen in `PrivacyLink.Contracts`.
- Gebruik één providerneutrale `IEmailSender`-interface met vorm `SendAsync(EmailMessage)`. De mailinhoud bevat ontvanger, onderwerp en tekst-/HTML-body; de applicatielaag bouwt de OTP-mail en de Resend-adapter verstuurt die. De Resend API-sleutel blijft servergeheim; het afzenderadres moet bij Resend geverifieerd zijn.
- Bewaar challenges, verificatiesessies en rate limits in PostgreSQL. Bestaande opslag- en secret-lifecyclecode uitbreiden waar dat past; geen tweede losse opslagroute toevoegen.
- De API biedt operaties om een OTP aan te vragen en te verifiëren. Metadata mag aangeven dat e-mailverificatie nodig is en het gemaskeerde adres teruggeven; nooit het volledige adres of de code.
- De backend controleert de OTP-sessie op iedere route die ciphertext, berichtinhoud of bestanden teruggeeft, waaronder open-, unlock- en bestandsroutes. Alleen geslaagde OTP-controle geeft een sessie uit. Een frontendcheck alleen is onvoldoende.
- Secretintrekking of -verloop maakt challenges en sessies meteen onbruikbaar, ook als fysieke opruiming later plaatsvindt.
- Challengevervanging, pogingtelling, codeconsumptie, limietreservering en sessie-uitgifte moeten veilig zijn bij gelijktijdige verzoeken.

### Technische invulling ter bevestiging bij implementatie

De volgende invulling is een aanbeveling om de afgesproken eigenschappen te realiseren; de spec schrijft geen concrete routenamen of databasetabellen voor:

- Sla de OTP niet leesbaar op. Gebruik een HMAC met een afzonderlijke servergeheime sleutel, plus constante-tijdvergelijking.
- Gebruik voor de verificatiesessie een willekeurig token in een `HttpOnly`, `Secure`-cookie met een vaste vervaltijd van 30 minuten. Bind het token server-side aan één secret en sla alleen een hash/HMAC van het token op. De precieze cookie-scope en `SameSite`-instelling sluiten aan op de bestaande same-origin deployment.
- Houd rollende limieten atomair bij in PostgreSQL. HMAC-gebaseerde identifiers voor e-mailadres en IP beperken de opslag van ruwe identificerende waarden.
- Sla een challenge op vóór verzending; maak hem ongeldig als Resend de verzending afwijst of niet bevestigt. Gebruik bestaande UTC-/`TimeProvider`-patronen voor verval en limieten.

## Gereed wanneer

1. Gewone secrets blijven werken zonder e-mailfactor; e-mailbeveiligde secrets vereisen PostgreSQL en een geldig adres.
2. Er wordt pas een OTP-mail verstuurd na een verzoek van de ontvanger; alleen het vooraf ingestelde, gemaskeerde adres is zichtbaar.
3. Codegeldigheid, eenmalig gebruik, drie pogingen, vervanging, sessieduur en alle afgesproken limieten werken zoals hierboven beschreven.
4. E-mailverificatie en PIN/wachtwoord zijn afzonderlijk te combineren en worden in de afgesproken volgorde afgedwongen.
5. Zonder geldige OTP-sessie geeft geen content- of bestandsroute gegevens vrij.
6. Resend-fouten, intrekking en verlopen secrets kunnen geen geldige OTP-sessie of challenge achterlaten.
7. De API lekt geen secretstatus of gevoelige mailgegevens via codeaanvragen, fouten of logs.
