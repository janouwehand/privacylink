# Specificatie: proof of work voor secret-aanmaak

Datum: 11 oktober 2026. Status: geïmplementeerd; productiecalibratie van de moeilijkheid vereist nog metingen op ondersteunde telefoons en onder gelijktijdige serverbelasting.

## Doel

Voeg een kleine proof-of-work-drempel toe aan iedere aanvraag voor `POST /api/v1/secrets`. Een gewone bezoeker laat de browser een beperkte SHA-256-berekening uitvoeren voordat de secret wordt verstuurd. Eenvoudige bots die alleen HTTP-requests versturen en deze berekening niet uitvoeren, kunnen daardoor geen secrets aanmaken.

Dit is een extra drempel tegen eenvoudige bots. Het is geen authenticatie, geen bewijs dat de aanvrager een mens is en geen DDoS-bescherming. Behoud de bestaande rate limits, requestlimieten, opslaglimieten en validatie.

## Scope

- Proof of work is vereist voor iedere create-aanvraag, ook wanneer die verder ongeldig zou zijn.
- De eis geldt voor zowel JSON-aanvragen als de bestaande geserialiseerde aanvraag voor uploads.
- De eis geldt alleen voor `POST /api/v1/secrets`. Openen, metadata opvragen, ontgrendelen en intrekken veranderen niet.
- De bestaande browserapp lost de puzzel op. De API blijft voor andere clients bruikbaar als die het proof meesturen.
- Gebruik geen CAPTCHA, account, cookie of derde-partijservice.

## Protocol

### Uitdaging ophalen

Voeg `GET /api/v1/secrets/create-challenge` toe. De endpoint maakt een nieuwe, willekeurige uitdaging aan en retourneert JSON:

```json
{
  "version": 1,
  "challengeId": "<base64url-id>",
  "nonce": "<base64url-nonce>",
  "difficultyBits": 20,
  "expiresAt": 1791747900,
  "signature": "<base64url-hmac-sha256>"
}
```

- `challengeId` en `nonce` zijn elk 128 bits uit een cryptografisch veilige randomgenerator en Base64URL-gecodeerd zonder padding.
- `difficultyBits` komt uitsluitend uit serverconfiguratie. De client mag de waarde niet verlagen of vervangen. Valideer de configuratie bij startup als een integer van 1 tot en met 24; bij een waarde daarbuiten start de API niet.
- `expiresAt` is de vervaltijd als canoniek decimaal Unix-tijdstip in seconden, maximaal vijf minuten na uitgifte.
- De server geeft de uitdaging stateless uit en bewaart haar niet. `signature` is HMAC-SHA-256 over de UTF-8-bytes van `PrivacyLink-Create-Challenge-v1\n<challengeId>\n<nonce>\n<difficultyBits>\n<expiresAt>`. Gebruik voor getallen canonieke decimale notatie zonder voorloopnullen.
- Codeer de 32-byte HMAC-uitkomst als Base64URL zonder padding.
- Gebruik voor HMAC een cryptografisch willekeurige sleutel van 32 bytes uit secretconfiguratie. Valideer de aanwezigheid en lengte bij startup. Alle API-instanties delen dezelfde sleutel; houd die buiten de broncode en logs. Een gecoördineerde sleutelrotatie maakt eerder uitgegeven uitdagingen ongeldig; de client haalt dan een nieuwe op.
- Antwoorden krijgen `Cache-Control: no-store`.
- Beperk challenge-aanvragen apart van create-aanvragen, per effectief client-IP. De limiet is per uur minimaal 20 en anders tweemaal de geconfigureerde create-limiet per uur; per dag minimaal 400 en anders viermaal de geconfigureerde create-limiet per dag. Challenge-aanvragen tellen niet mee voor de create-limiet. Deze minimums bieden ruimte voor één zichtbare pagina die ongeveer iedere vier minuten ververst (circa 15 uitdagingen per uur en 360 per dag), met enige ruimte voor extra aanvragen.
- Een challenge ophalen slaat geen challenge of replay-record op, maakt geen secret aan en gebruikt geen blobruimte.
- Bij overschrijding van de IP-limiet retourneert de endpoint HTTP 429 met `code=rate_limited` en `Retry-After`.

### Bewijs berekenen

De client zoekt een niet-negatieve 64-bits teller `counter`, beginnend bij nul, waarvoor de eerste `difficultyBits` bits van deze SHA-256-uitkomst allemaal nul zijn:

```text
SHA-256(UTF-8("PrivacyLink-Create-PoW-v1:" + challengeId + ":" + nonce + ":" + counter))
```

Gebruik de letterlijke Base64URL-waarden uit de uitdaging en de teller als canonieke decimale notatie zonder voorloopnullen. De teller is maximaal 20 ASCII-cijfers en ligt tussen 0 en `2^64 - 1`. De server voert exact dezelfde byte- en stringopbouw uit. Tel nulbits vanaf het meest significante bit van de eerste hashbyte, daarna van links naar rechts door de digest. Bij `difficultyBits = 20` moeten bijvoorbeeld de eerste 20 bits van de 256-bits hash nul zijn. De waarde 20 is alleen een protocolvoorbeeld, geen productie-instelling.

Voer de zoektocht in de browser asynchroon uit, zodat de pagina responsief blijft. Toon tijdens de berekening de bestaande voortgangsstatus met een korte melding, bijvoorbeeld “Aanvraag voorbereiden”. De gebruiker kan de berekening afbreken wanneer die het aanmaakproces annuleert.

### Create-aanvraag

Stuur het bewijs mee in een HTTP-header, zodat de API het kan controleren voordat zij de requestbody leest:

```http
X-PrivacyLink-Proof: <challengeId>.<nonce>.<difficultyBits>.<expiresAt>.<signature>.<counter>
```

De client gebruikt exact de waarden uit het challenge-antwoord. De header bevat uitsluitend ASCII en is maximaal 160 bytes. De server controleert in deze volgorde:

1. De bestaande client-IP-rate-limit voor secret-aanmaak.
2. Aanwezigheid, maximale lengte en syntaxis van alle proof-header-velden; decodeer de handtekening canoniek als exact 32 bytes.
3. De HMAC-handtekening met een constant-time vergelijking, de vervaltijd en de grenzen van `difficultyBits`.
4. Of de SHA-256-uitkomst aan de ondertekende moeilijkheid voldoet.
5. Of `challengeId` nog ongebruikt is; registreer de ID atomair als gebruikt tot `expiresAt`.
6. Pas daarna de bestaande body-, JSON-, bestand-, password- en secretvalidatie en opslag.

Het bewijs geldt één keer. De replay-opslag bevat uitsluitend challenge-ID’s waarvoor een geldig bewijs is aangeboden; uitgegeven maar ongebruikte uitdagingen nemen geen opslagruimte in. Een verlopen, al gebruikt, niet-ondertekend of ongeldig bewijs levert dezelfde generieke fout op. Een ontbrekend of ongeldig bewijs geeft HTTP 403 met `code=proof_required`; de API leest de body niet en maakt geen secret aan. Als de replay-opslag vol of niet beschikbaar is, retourneert de API HTTP 503 met `code=temporarily_unavailable` en `Retry-After: 5`, zonder de body te lezen. Behoud de bestaande auditregistratie voor de create-aanvraag en registreer de afwijzing als `rejected`.

Bij een HTTP 403 met `code=proof_required` haalt de browser een nieuwe uitdaging op en probeert die één keer opnieuw. Andere HTTP 403-responses leiden niet tot een retry; de UI toont daarvoor de bestaande generieke foutmelding. Na een tweede `proof_required`-afwijzing toont de UI eveneens de bestaande generieke foutmelding. Een create-poging die na bewijsvalidatie door andere validatie faalt, heeft een nieuwe uitdaging nodig voor een nieuwe aanvraag.

Proof of work voorkomt niet dat requestbytes al over het netwerk zijn verzonden en voorkomt evenmin dat een reverse proxy de body vooraf buffert. “Vóór bodyverwerking” betekent dat de applicatie de body niet parseert of opslaat voordat het bewijs geldig is. Proxy- en serverlimieten voor bodygrootte en requestduur blijven nodig.

## Browserintegratie

- Start bij het openen van de zichtbare aanmaakpagina direct één challenge-aanvraag en laat een Worker de oplossing berekenen. De browser mag de berekening starten voordat de gebruiker op “aanmaken” klikt.
- Gebruik één Worker en laat nooit meerdere proof-berekeningen tegelijk lopen. Houd een gevonden proof alleen in vluchtig geheugen; schrijf challenge, teller en proof niet naar `localStorage`, `sessionStorage`, de URL, de gedeelde link, logs of auditregels.
- Een gevonden proof blijft bruikbaar totdat de uitdaging verloopt of het proof bij een create-aanvraag wordt gebruikt. Reken een nog geldig proof niet opnieuw uit.
- Als de uitdaging nog hoogstens 60 seconden geldig is, vraag dan een vervangende uitdaging aan en reken die alvast uit zolang de aanmaakpagina zichtbaar is. Dit kan ook als de gebruiker op dat moment geen directe toetsenbord-, muis- of touchactie uitvoert. Houd het bestaande proof bruikbaar totdat de vervanging klaar is; bewaar daarna alleen de nieuwste proof.
- Gebruik geen doorlopende `setInterval` die steeds opnieuw rekent. Controleer de vervaltijd met een timer en opnieuw wanneer de pagina zichtbaar wordt en bij een klik op “aanmaken”. Is het proof verlopen, ontbreekt het of wordt het nog berekend, haal dan zo nodig een nieuwe uitdaging op en wacht op de Worker voordat de create-aanvraag wordt verstuurd.
- Start geen nieuwe berekening op een verborgen pagina en annuleer een lopende berekening wanneer de pagina verborgen wordt, bij navigatie of wanneer de gebruiker het aanmaken annuleert. Controleer bij terugkeer de geldigheid van het huidige proof; vraag alleen een nieuwe uitdaging aan als het proof ontbreekt, verlopen is of binnen 60 seconden verloopt. Houd een bestaand geldig proof bruikbaar totdat de vervanging klaar is.
- Gebruik dezelfde flow voor de gewone JSON-request en de geserialiseerde upload-request.
- Bereken SHA-256 met de browsercrypto-API. Houd de UI responsief en toon tijdens het rekenen de bestaande voortgangsstatus, bijvoorbeeld “Aanvraag voorbereiden”.
- Na iedere create-aanvraag wordt het proof weggegooid, ook bij een netwerkfout, omdat de server het mogelijk al heeft verbruikt. Bij de beschreven HTTP 403-flow haalt de client een verse uitdaging op, rekent opnieuw en probeert één keer opnieuw.

## Serveropslag en schaal

Bewaar alleen geconsumeerde `challengeId`-waarden en hun vervaltijd, maximaal 10.000 actieve entries in totaal. Verwijder verlopen entries periodiek. Bij volle of niet-beschikbare replay-opslag weigert de API secret-aanmaak tijdelijk met de hierboven beschreven HTTP 503-response; challenge-uitgifte blijft mogelijk omdat die stateless is.

De replay-opslag moet een atomaire insert-if-absent bieden en entries behouden tot hun vervaltijd, ook na een API-procesherstart. Bij meerdere API-instanties gebruiken alle instanties dezelfde replay-opslag en HMAC-sleutel. Een ID mag niet opnieuw geldig worden door gelijktijdige requests, een andere instantie of een procesherstart. Gebruik geen sticky sessions als beveiligingsgarantie.

## Moeilijkheid en configuratie

- Maak de moeilijkheid configureerbaar als een integer aantal leidende nulbits tussen 1 en 24. Valideer deze grens bij startup en laat de API niet starten bij een ongeldige waarde.
- Kalibreer de startwaarde op ondersteunde telefoons zodat de berekening op een normale telefoon ongeveer drie seconden duurt. De waarde moet uit metingen komen; neem de voorbeeldwaarde `20` uit het protocolvoorbeeld niet klakkeloos als productie-instelling over.
- Houd de moeilijkheid vast voor de levensduur van een uitdaging. Verhoog of verlaag haar alleen via serverconfiguratie en geef de actuele waarde mee in elke nieuwe uitdaging.
- Een te hoge moeilijkheid maakt de app onbruikbaar op langzamere apparaten; een te lage moeilijkheid maakt de botdrempel verwaarloosbaar. Meet daarom zowel rekentijd op telefoons als CPU-kosten onder gelijktijdig gebruik.
- Laat bestaande create-rate-limits en body-/opslaglimieten actief. Proof of work vervangt die controles niet.

## Privacy en beveiliging

- De uitdaging bevat geen geheime waarde, secretinhoud, wachtwoord, clientkey of persoonlijk gegeven.
- De HMAC-sleutel is een servergeheim en komt nooit in responses, logs of auditregels. De challengehandtekening zelf is geen geheim.
- De challenge-endpoint en create-endpoint blijven HTTPS-only in productie.
- Vertrouw voor rate limiting alleen het effectieve IP na verwerking van expliciet vertrouwde proxies. Lees geen willekeurige `X-Forwarded-For`-header.
- Limiteer challenge-uitgifte en houd replay-opslag en proof-header strikt begrensd.
- De server valideert het bewijs zelf; een clientstatus zoals “opgelost” wordt nooit vertrouwd.
- De moeilijkheid is een kostenverhoging voor clients, geen geheime formule. Een bot die SHA-256 uitvoert kan het bewijs oplossen; dit ontwerp richt zich op eenvoudige bots die de stap niet implementeren.

## Acceptatiecriteria

1. Iedere create-aanvraag zonder bruikbaar bewijs wordt vóór bodyverwerking afgewezen en maakt geen secret of blob aan.
2. Een geldig bewijs voor een geldige uitdaging staat precies één create-aanvraag toe.
3. Een verlopen, gebruikt, onbekend, verkeerd gevormd of onvoldoende bewijs wordt generiek afgewezen en maakt geen secret aan.
4. Hetzelfde gedrag geldt voor JSON- en geserialiseerde upload-aanvragen.
5. Bij het openen van de zichtbare aanmaakpagina start de browser één Worker die een uitdaging oplost; het rekenen duurt op een normale telefoon circa drie seconden en blokkeert de UI niet.
6. Een geldig, ongebruikt proof blijft beschikbaar tot gebruik of verval. De client rekent niet opnieuw zolang het proof geldig is.
7. De client ververst een proof dat binnen 60 seconden verloopt zolang de pagina zichtbaar is, ook zonder recente gebruikersactie. Bij verbergen annuleert de client een lopende berekening. Bij terugkeer behoudt de client een geldig proof en vernieuwt alleen als het ontbreekt, verlopen is of binnen 60 seconden verloopt.
8. Bij een create-aanvraag zonder geldig voorbereid proof lost de client eerst een verse uitdaging op. Een tijdelijke netwerkfout of clientretry kan geen tweede secret met hetzelfde bewijs aanmaken.
9. Challenge-aanvragen zijn per IP beperkt tot minimaal 20 per uur en anders tweemaal de create-limiet per uur, en minimaal 400 per dag en anders viermaal de create-limiet per dag. Deze minimums bieden ruimte voor één zichtbare pagina die ongeveer iedere vier minuten ververst. Challenge-uitgifte slaat geen challenge op.
10. De replay-opslag bevat maximaal 10.000 actieve, geconsumeerde challenge-ID’s in totaal. Uitdagingen vervallen automatisch; gelijktijdig gebruik, gebruik via een andere instantie of replay na een procesherstart kan dezelfde uitdaging niet tweemaal consumeren. Volle of niet-beschikbare replay-opslag geeft de beschreven 503-response.
11. Bestaande create-rate-limits, validatie, audits, requestlimieten en opslaglimieten blijven actief en behouden hun bestaande betekenis.
12. Openen, metadata, ontgrendelen en intrekken blijven ongewijzigd.
13. Documentatie beschrijft dat proof of work eenvoudige bots afremt, geen inkomend netwerkverkeer tegenhoudt en geen bescherming tegen DDoS of geavanceerde bots garandeert.
