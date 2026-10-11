# Specificatie: audit van secretrequests

Datum: 11 oktober 2026. Status: klaar voor implementatie; nog niet geïmplementeerd.

## Doel en scope

Registreer in PostgreSQL iedere serveraanvraag die betrekking heeft op een secret, zowel geslaagde als afgewezen of mislukte aanvragen. De registratie is een audittrail per HTTP-request. Deze wijziging voegt geen rapportage of statistiekberekening toe.

Binnen scope vallen:

| Request | Actie |
| --- | --- |
| `POST /api/v1/secrets` | `create` |
| `GET /api/v1/secrets/{id}` | `metadata` |
| `POST /api/v1/secrets/{id}/open` | `open` |
| `POST /api/v1/secrets/{id}/unlock` | `unlock` |
| `POST /api/v1/secrets/{id}/files/{fileId}/open` | `file_open` |
| `POST /api/v1/secrets/{id}/revoke` | `revoke` |
| Een HTTP-request voor `/s/{id}` dat de applicatie bereikt | `secret_page` |
| Onbekende methode of subroute onder de secret-API | `secret_request` |

Ook requests die eindigen in bijvoorbeeld 400, 403, 404, 405, 413, 415, 429 of 5xx worden geregistreerd. Behoud de bestaande statuscode en foutsemantiek; maak een 404 niet specifieker als dat het bestaan van een secret kan onthullen. De garantie geldt vanaf het moment dat de applicatie het request ontvangt en als secretrequest kan classificeren. Afwijzingen door een proxy of HTTP-server vóór dat punt zijn niet zichtbaar voor de audit.

Healthchecks, capabilities, de oude statsroute, algemene websitebestanden en lokale SPA-navigatie vallen buiten scope. Automatische expirycleanup is geen HTTP-request en krijgt geen auditregel.

## Auditregel en secret-ID

Maak in migratie 7 de tabel `secret_request_audit` aan. Elke HTTP-poging krijgt precies één regel, met een servergegenereerde unieke `request_id`. Interne schrijf-retries gebruiken dezelfde ID; een nieuwe clientaanvraag krijgt een nieuwe ID.

`secret_id` is verplicht, niet leeg, een canonieke Base64URL-ID van 22 tekens en heeft geen foreign key naar `secrets`. Auditregels blijven daardoor bestaan nadat een secret is verwijderd of wanneer het aangevraagde ID nooit heeft bestaan.

Voor `POST /api/v1/secrets` genereert de server een secret-ID vóór validatie en andere applicatie-afwijzingen. Bij succes is dit hetzelfde ID als dat van de opgeslagen secret en de response. Bij afwijzing blijft het ID alleen in de audit; er wordt geen secretrecord aangemaakt. Iedere nieuwe create-aanvraag krijgt een nieuw ID.

Requests met een bruikbaar ID in de route gebruiken dat als `secret_id`, ook als het secret onbekend of verwijderd is. Als een secretrequest geen bruikbaar route-ID heeft, reserveert de server een ID voor de auditregel. Gebruik geen gedeeld dummy-ID. `secret_id_source` (`route` of `reserved`) maakt de herkomst duidelijk. Een onbruikbaar aangeleverd ID mag begrensd in `requested_secret_id` worden bewaard, uitsluitend als onbetrouwbare invoer.

De tabel bevat ten minste deze gegevens:

| Veld | PostgreSQL-type | Nullability en betekenis |
| --- | --- | --- |
| `id` | `bigint GENERATED ALWAYS AS IDENTITY` | NOT NULL, primary key. |
| `request_id` | `uuid` | NOT NULL, uniek; servergegenereerd. |
| `trace_id` | `text` | NOT NULL; servercorrelatie voor operationele logs. |
| `secret_id` | `text` | NOT NULL; canonieke Base64URL-ID van 22 tekens, zonder FK. |
| `secret_id_source` | `text` | NOT NULL; `route` of `reserved`. |
| `requested_secret_id` | `text` | NULL toegestaan; begrensd, alleen voor een onbruikbaar route-ID. |
| `action` | `text` | NOT NULL; een actie uit de scope-tabel hierboven. |
| `http_method` | `text` | NOT NULL; ontvangen methode. |
| `route_template` | `text` | NOT NULL; bekende route of vaste categorie, nooit de volledige URL. |
| `started_at` | `timestamptz` | NOT NULL; UTC-starttijd. |
| `completed_at` | `timestamptz` | NULL toegestaan zolang de request nog loopt; UTC-eindtijd. |
| `duration_ms` | `bigint` | NULL toegestaan zolang de request nog loopt; anders niet-negatief. |
| `state` | `text` | NOT NULL; `started`, `completed` of `aborted`. |
| `outcome` | `text` | NULL toegestaan zolang `started`; anders `success`, `rejected`, `error` of `aborted`. |
| `http_status` | `smallint` | NULL toegestaan; gekozen status, indien bekend, tussen 100 en 599. |
| `error_code` | `text` | NULL toegestaan; gecontroleerde code, nooit exceptiontekst. |
| `client_ip` | `inet` | NULL alleen als geen IP beschikbaar is; leesbaar hostadres. |
| `file_id` | `text` | NULL toegestaan; bestand-ID bij een afzonderlijk bestandrequest. |

Leg benoemde waardenlijst-, lengte- en levenscycluschecks vast in migratie 7. De levenscycluscheck moet exact afdwingen: `started` vereist NULL voor `completed_at`, `duration_ms`, `outcome`, `http_status` en `error_code`; `completed` vereist NOT NULL voor `completed_at`, `duration_ms` en `outcome`, waarbij `outcome` een van `success`, `rejected` of `error` is; `aborted` vereist NOT NULL voor `completed_at` en `duration_ms` en `outcome='aborted'`, terwijl `http_status` optioneel blijft. Bij beide eindstatussen is `error_code` optioneel. Een check op `duration_ms` dwingt af dat een ingevulde waarde niet-negatief is. Gebruik expliciete checks zodat SQL-NULL-semantiek de lifecyclevoorwaarden niet omzeilt. Voeg indexen toe op `(secret_id, started_at, id)` en `(started_at, id)`; de unieke constraint op `request_id` levert de bijbehorende index. Er is geen update-/deletepad voor afgeronde auditregels.

## Registratiegedrag

Classificeer secretrequests na verwerking van vertrouwde forwarded headers en vóór rate limiting, validatie of andere applicatie-afwijzingen. Schrijf eerst één `started`-regel. Voer de secretactie niet uit wanneer die insert faalt: retourneer HTTP 503 met `code=audit_unavailable`.

Rond de bestaande regel af met uitkomst, gekozen status en foutcode vóórdat een succesresponse of secretinhoud naar de client wordt vrijgegeven. Als de afronding faalt, geef geen succesresponse of inhoud vrij; retourneer 503 zolang de response nog niet is gestart. Als de verbinding al weg is of een proces stopt, mag een regel als `started` achterblijven of als `aborted` worden vastgelegd wanneer dat nog betrouwbaar kan. Een onafgeronde regel is nooit een succes.

Als een secretmutatie in PostgreSQL plaatsvindt, commit de mutatie samen met de eindstatus van de auditregel. Zo kan een auditfout geen ongeregistreerde create of revoke opleveren. Voor reads wordt inhoud pas vrijgegeven nadat de auditregel is afgerond. Bij unlock blijft de attempt-reservering vóór de wachtwoord-KDF apart duurzaam vastgelegd, zoals de bestaande beveiliging vereist. Na een geslaagde KDF worden de attempt-reset en de succesvolle audituitkomst samen vastgelegd; geef inhoud pas daarna vrij. Houd bestaande unlockattempt-beveiliging en responsecontracten in stand.

Een auditregel beschrijft wat de server heeft verwerkt en welke response hij heeft gekozen; ze bewijst niet dat de client alle bytes heeft ontvangen. Eén unlockrequest met meerdere bestanden blijft één regel. Een metadatarequest gevolgd door open zijn twee regels. Clientacties zonder serverrequest, zoals lokaal ontsleutelen of kopiëren, zijn niet zichtbaar.

## IP, toegang en bewaring

Gebruik het effectieve client-IP nadat de bestaande verwerking voor expliciet vertrouwde proxies is toegepast. Lees niet zelf een willekeurige `X-Forwarded-For`-header. Normaliseer IPv4-mapped IPv6 naar IPv4 en sla adressen op zonder poort. Het IP is leesbaar opgeslagen.

Auditregels en IP-adressen worden in deze versie onbeperkt bewaard, ook na verwijdering van het secret. Er komt geen publieke audit-API, pagina of export. Toegang loopt via bestaande geautoriseerde database-/beheerrechten. Werk bij implementatie de Nederlandse en Engelse privacy- en beveiligingsteksten bij zodat deze bewaring duidelijk wordt beschreven.

## Oude statistieken en migratie

De oude statistiekverzameling is al verwijderd. Laat migraties 1–6 ongewijzigd. Migratie 7 maakt de audittabel aan en werkt op zowel een verse database als een database met bestaande secrets. Voeg geen historische auditregels toe en wijzig of reset geen bestaande secrets.

Behoud het huidige tijdelijke gedrag: `/api/v1/stats` retourneert HTTP 410 (`statistics_retired`) en `/stats` toont dat statistieken niet beschikbaar zijn. Verwijder bij implementatie eventuele resterende oude stats-writers, lezers, daglocks en ongebruikte `Analytics:Key`-configuratie. Behoud `Security:AuditHashKey` zolang diagnostische logs die gebruiken. Diagnostische logs en bestaande rate limiting blijven functioneren.

De bestaande secretopslag, encryptie, expiratie, intrekking en blobverwijdering blijven behouden. Deze wijziging introduceert geen blob-cleanupwachtrij, blobreconciliatie, nieuwe cleanupworker, nieuwe rapportage, materialized view, dashboard of auditinzagescherm. Oude statistiekgegevens worden niet hersteld.

## Acceptatiecriteria

1. Ieder door de applicatie herkend secretrequest maakt precies één auditregel, ook bij validatiefouten, verkeerde wachtwoorden, rate limiting, origin-/HTTPS-afwijzingen en onbekende, verlopen of verwijderde secrets. Uitgesloten requests maken geen auditregel.
2. Iedere create-poging heeft vóór validatie een eigen secret-ID. Bij een succesvolle create zijn het audit-, opslag- en response-ID gelijk; een afgewezen create maakt geen secretrecord.
3. Een secretrequest zonder bruikbaar route-ID krijgt een gereserveerd audit-ID. Een request naar een onbekend of verwijderd secret kan zonder foreign-keyfout worden vastgelegd.
4. Een HTTP-request naar de secretpagina en een afzonderlijke bestandsaanvraag worden elk geregistreerd. Eén unlock met meerdere bestanden blijft één requestregel.
5. Client-IP komt uit de bestaande vertrouwde proxyverwerking. IPv4, IPv6 en IPv4-mapped IPv6 worden correct en leesbaar opgeslagen; onbetrouwbare forwardingheaders veranderen het adres niet.
6. Als de initiële auditinsert faalt, wordt de secretactie niet uitgevoerd en krijgt de client 503 `audit_unavailable`. Als de auditafronding faalt, wordt geen succesresponse of secretinhoud vrijgegeven. PostgreSQL-mutaties en de audituitkomst worden atomair vastgelegd.
7. Auditregels blijven na intrekking, expiratie en opruiming van een secret bestaan. Bestaande secrets blijven bruikbaar en worden door migratie 7 niet gewijzigd.
8. Bij unlock blijft de attempt-reservering duurzaam staan bij een fout wachtwoord of latere auditstoring. Na succesvolle authenticatie worden de attempt-reset en audituitkomst samen vastgelegd vóór vrijgave van inhoud.
9. Oude stats blijven verwijderd; de tijdelijke stats-API en -pagina blijven zonder oude cijfers functioneren. Er worden geen nieuwe statistiekberekeningen of dashboards toegevoegd.
10. Documentatie beschrijft de onbeperkte bewaring van secretrequesthistorie, secret-ID's en leesbare IP-adressen.
