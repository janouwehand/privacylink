# Spec: registratie van secretrequests ter vervanging van oude stats

Datum: 10 oktober 2026. Status: uitgewerkte specificatie; nog niet geïmplementeerd.

## Doel en vastgestelde keuzes

Vervang de huidige statistiekverzameling door één audit-/trackingtabel die elk serverrequest met betrekking tot een secret registreert. De tabel bewaart individuele requests en zinvolle context. Later dient deze als bron voor een materialized view voor nieuwe statistieken; die view en die statistieken vallen buiten deze wijziging.

Vastgesteld met de opdrachtgever:

- Elk request met betrekking tot een secret telt, inclusief metadata, bestanden, mislukte pogingen en afwijzingen. Healthchecks, capabilities en algemene websitebestanden tellen niet.
- Elke auditregel heeft een niet-leeg, niet-null `secret_id`. Dit is een logische verwijzing, zonder technische foreign key naar `secrets`.
- Iedere aanmaakpoging krijgt vooraf een servergegenereerd secret-ID, ook als aanmaken mislukt of het request vroeg wordt afgewezen.
- Auditregels blijven bestaan als het secret onbekend, verlopen of verwijderd is. De secretrecord hoeft daarvoor niet behouden te worden.
- Het leesbare client-IP wordt geregistreerd. Auditregels en IP-adressen worden onbeperkt bewaard.
- Registratie is strikt: als registreren mislukt, moet het request falen.
- De oude statistiekgegevens mogen verdwijnen. Er vindt geen reconstructie van historische requests plaats.
- Bestaande secrets blijven werken. Zij krijgen vanaf de overgang een gedeeltelijke audittrail.

De concrete veldnamen, technische aanpak en tijdelijke behandeling van de oude statistiekenpagina hieronder zijn ontwerpkeuzes binnen deze uitgangspunten.

## Huidige situatie

`src/PrivacyLink.Api/Statistics.cs` schrijft dagtotalen naar `stats_daily` en IP-HMACs naar `stats_visitors_daily`. `StatisticsFinalizer` finaliseert dagen met advisory locks en verwijdert oude dagtotalen. De endpoints registreren deels zelf; aparte middleware registreert sommige foutcategorieën. Aanmaken levert meerdere statistiekregels op en is gekoppeld aan de dagfinalisatie. Andere statistiekschrijffouten worden momenteel gelogd zonder het request te laten falen.

`PrivacyAudit.cs` verzorgt daarnaast operationele applicatielogs. Deze zijn geen bron voor de huidige dagtotalen. De database-audit wordt de bron voor secretrequesthistorie; reguliere diagnostische logs blijven beschikbaar voor storingen.

Intrekken en opruimen verwijderen momenteel secretrecords en blobs. Deze verwijdersemantiek blijft behouden: auditretentie mag secretinhoud niet langer beschikbaar houden.

## Wat is één actie?

Eén inkomend HTTP-request binnen de scope correspondeert met één auditregel. Het ophalen van meerdere bestanden in één unlockresponse blijft één request met een bestandaantal en byteaantal; afzonderlijke bestandrequests leveren afzonderlijke regels op. Metadata opvragen en daarna openen zijn twee acties.

Browserretries zijn afzonderlijke requests. Een retry van dezelfde interne auditschrijfactie mag geen extra regel maken. Clienthandelingen zonder serverrequest, zoals lokaal ontsleutelen, kopiëren of het delen van een link, worden niet geregistreerd. Een geslaagd openrequest bewijst dat de API inhoud voor verstrekking heeft voorbereid, niet dat een ontvanger die heeft gelezen.

### Requestscope

| Request | Actie |
| --- | --- |
| `POST /api/v1/secrets` | `create` |
| `GET /api/v1/secrets/{id}` | `metadata` |
| `POST /api/v1/secrets/{id}/open` | `open` |
| `POST /api/v1/secrets/{id}/unlock` | `unlock` |
| `POST /api/v1/secrets/{id}/files/{fileId}/open` | `file_open` |
| `POST /api/v1/secrets/{id}/revoke` | `revoke` |
| Een daadwerkelijke serveraanvraag van de secretpagina `/s/{id}` | `secret_page` |
| Andere methoden of onbekende subroutes binnen de secret-API | `secret_request` |

De secretpagina wordt alleen geregistreerd als een HTTP-request de applicatie bereikt. Een lokale SPA-routewissel is geen serverrequest. Als een proxy een secretpagina zelf afhandelt, is dat request niet zichtbaar voor de applicatie; controleer bij implementatie of zulke requests naar de applicatie moeten worden doorgestuurd.

Ook 400, 403, 404, 405, 413, 415, 429 en 5xx binnen deze scope worden geregistreerd, inclusief afwijzingen door HTTPS-/originbeleid, requestvalidatie, rate limiting, opslagcapaciteit en wachtwoordbeveiliging. Leg de werkelijk gekozen foutcode vast; verander geen bestaande 404 in een specifiekere fout die het bestaan van een secret onthult.

Uitgesloten zijn `/health`, `/health/ready`, `/api/v1/capabilities`, de oude statsroute en algemene HTML-, script-, CSS-, favicon- en afbeeldingsrequests zonder relatie met één secret. Automatische expirycleanup is geen serverrequest en krijgt in deze fase geen zelfstandige auditactie. Verlopen secrets blijven bij toegangsrequests dezelfde afwijzingssemantiek houden.

Requests die door de proxy, HTTP-server of hostvalidatie worden verworpen voordat ze de applicatie-audit bereiken, kunnen niet door deze tabel worden geregistreerd. De garantie geldt vanaf het moment dat de applicatie het request ontvangt en als secretrequest herkent.

## Secret-ID vóór verwerking

Bij `POST /api/v1/secrets` genereert de server één ID vóór bodyvalidatie, rate limiting en andere afwijzingen binnen de applicatie. Het endpoint gebruikt exact dat ID wanneer het secret daadwerkelijk wordt opgeslagen. Reserveren betekent hier een ID genereren voor het request; het maakt nog geen secretrecord en telt niet mee voor de capaciteit voor actieve secrets.

Bij een request met een bruikbaar route-ID wordt dat ID opgeslagen, ook als er geen bijbehorend secret meer bestaat. Een afwijzing van een onbekend ID hoeft dus nooit over te slaan wegens referentiële integriteit.

Voor malformed secretrequests zonder bruikbaar ID wordt een servergegenereerd ID gereserveerd voor de auditregel. Gebruik geen gedeeld dummy-ID. `secret_id_source` onderscheidt een ID uit de route van een gereserveerd ID. Een ongeldig aangeleverd route-ID kan daarnaast begrensd worden vastgelegd als `requested_secret_id`; behandel dat als onbetrouwbare invoer. Hiermee suggereert een auditregel niet dat een geldig secret heeft bestaan.

Een aanmaakpoging die vroeg wordt afgewezen hoeft zijn gereserveerde ID niet aan de client bekend te maken. Een volgende HTTP-poging krijgt een nieuw gereserveerd ID. Bestaande successresponsecontracten blijven gelijk.

## Datamodel

Introduceer `secret_request_audit` in dezelfde PostgreSQL-database als de secrets. De relatie met `secrets.id` is uitsluitend logisch: geen FK, geen cascade, geen secretlookup als voorwaarde om een auditregel te mogen schrijven.

| Veld | Type / verplicht | Betekenis |
| --- | --- | --- |
| `id` | `bigint`, gegenereerde primary key | Identiteit van de auditregel. |
| `request_id` | `uuid`, uniek, NOT NULL | Door de server gemaakte identiteit van dit HTTP-request; ook voor interne schrijf-retries. |
| `trace_id` | `text`, NOT NULL | Correlatie met operationele logs; door de server bepaald. |
| `secret_id` | `text`, NOT NULL, niet leeg | Route-ID of vooraf gereserveerd ID, zonder FK. |
| `secret_id_source` | `text`, NOT NULL | `route` of `reserved`. |
| `requested_secret_id` | `text`, optioneel | Alleen zinvolle, begrensde context wanneer een ongeldig route-ID niet als `secret_id` bruikbaar is. |
| `action` | `text`, NOT NULL | Een actietype uit de requestscope. |
| `http_method` | `text`, NOT NULL | Ontvangen HTTP-methode. |
| `route_template` | `text`, NOT NULL | Bekende routetemplate; bij een onbekende subroute een vaste categorie, geen volledige URL. |
| `started_at` | `timestamptz`, NOT NULL | Moment van binnenkomst volgens de server, vastgelegd in UTC. |
| `completed_at` | `timestamptz`, optioneel | Tijdstip waarop de afhandeling is afgerond. |
| `duration_ms` | `bigint`, optioneel, niet negatief | Verstreken verwerkingstijd; meet met een monotone klok. |
| `state` | `text`, NOT NULL | `started`, `completed` of `aborted`. |
| `outcome` | `text`, optioneel | `success`, `rejected`, `error` of `aborted`. |
| `http_status` | `smallint`, optioneel | Status die de server voor de response heeft gekozen; geen bewijs van aflevering aan de client. |
| `error_code` | `text`, optioneel | Een gecontroleerde applicatiecode, geen exceptiontekst. |
| `error_category` | `text`, optioneel | Bijvoorbeeld `validation`, `authorization`, `not_found`, `rate_limit`, `capacity`, `server_error` of `audit_unavailable`. |
| `client_ip` | `inet`, optioneel | Leesbaar, genormaliseerd client-IP; null uitsluitend als de verbinding geen IP beschikbaar stelt. |
| `file_id` | `text`, optioneel | Betrokken bestand bij een afzonderlijk bestandrequest, zonder FK. |
| `context` | `jsonb`, NOT NULL, standaard `{}` | Begrensde, expliciet toegestane metadata; geen automatische serialisatie van request of secretrecord. |

Regels voor het model:

- Een afgeronde regel heeft `completed_at`, `duration_ms` en `outcome`. Een HTTP-status is niet verplicht bij een verbroken verbinding.
- `started` betekent dat het request is ontvangen, maar de uitkomst nog niet duurzaam is vastgesteld. Het mag nooit als succes worden behandeld.
- `request_id` zorgt voor idempotente interne auditwrites. Vertrouw hiervoor niet op een clientheader.
- Voeg beperkte indexen toe op `(secret_id, started_at, id)` en `(started_at, id)`. De unieke index op `request_id` komt uit de constraint. Nieuwe rapportage-indexen volgen pas als de materialized view wordt ontworpen.
- Er is geen automatische verwijdering, anonimisering of rotatie van auditregels. De tabel blijft buiten de capaciteitstelling en cleanup voor actieve secrets.
- Afronden mag de initiële context aanvullen. Afgeronde regels worden niet meer functioneel gewijzigd; geen algemene update-/deletefunctie voor audithistorie.

### Zinvolle context

Gebruik een expliciete allowlist voor `context`. Voor succesvolle aanmaak zijn inhoudstype (`text`, `files`, `both`), aanwezigheid van een bericht, aantal bestanden, wachtwoordbescherming, protocolversie, gekozen vervalduur en berekende `expires_at` zinvol. Deze snapshot blijft beschikbaar nadat het secret is verwijderd. Bestaande secrets krijgen dergelijke context alleen uit werkelijk beschikbare informatie bij latere requests, zonder fictieve aanmaakactie.

Bij open-/unlock-/bestandrequests zijn `returned_file_count`, `returned_file_plaintext_bytes` en `returned_message_ciphertext_bytes` zinvol, voor zover werkelijk voorbereid voor de response. Houd gedeclareerde plaintext-bestandbytes en ciphertextbytes apart; het zijn geen daadwerkelijk gemeten netwerkbytes. Bij een afwijzing zijn een gecontroleerde foutcategorie en eventuele retry-afterduur zinvol. Onbekende waarden ontbreken; vul ze niet met nul alsof ze gemeten zijn.

Sla geen berichtinhoud, ciphertextpayloads, bestandsnamen, wachtwoorden, PINs, passwordtokens, clientkeys, revoke tokens of hashes daarvan op. Neem ook geen request-/responsebody, cookies, authorizationheaders, querystrings, volledige links, URL-fragmenten of ongefilterde exceptionteksten op. User-agent, referer en overige headers zijn in deze fase niet nodig.

Het bewaren van zinvolle metadata betekent niet dat elk serverzichtbaar gegeven wordt gekopieerd naar de audit.

## Leesbaar IP-adres

Gebruik het effectieve client-IP uit de verbinding nadat de bestaande verwerking voor expliciet vertrouwde proxies heeft plaatsgevonden. Lees niet rechtstreeks een willekeurige `X-Forwarded-For`-header uit. De bestaande proxyvertrouwensgrens blijft gelden.

IPv4-mapped IPv6-adressen worden genormaliseerd naar IPv4 zodat dezelfde verbinding niet twee schrijfwijzen krijgt. Bewaar IPv4 en IPv6 als valide adressen zonder poort. Gebruik null wanneer het IP ontbreekt, geen fictief adres of tekstwaarde `unknown` in het adresveld. Voor reguliere netwerkrequests hoort een leesbaar adres aanwezig te zijn.

Het leesbare IP staat in de audittabel. Er komt geen publieke audit-API, auditpagina of export in deze fase. Toegang verloopt via bestaande geautoriseerde database-/beheerrechten. Reguliere operationele logs hoeven het leesbare IP en de secret-ID niet te dupliceren.

## Strikte registratie en verwerking

De eenvoudige centrale levenscyclus is: request herkennen en identificeren, een regel met `state=started` duurzaam schrijven, de actie verwerken en dezelfde regel duurzaam afronden vóór vrijgave van de response. Eén request levert zo één regel op, met normaal één insert en één update. Er is geen queue of achtergrondtaak die registratie vrijblijvend later uitvoert.

1. Plaats registratie na de verwerking van vertrouwde forwarded headers en vóór applicatie-afwijzingen van secretrequests. De classificatie moet ook vóór de uitvoering van rate limiting en endpoints beschikbaar zijn.
2. Als de initiële insert niet slaagt, voer de secretactie niet uit en retourneer HTTP 503 met `code=audit_unavailable`. Verstrek geen secretinhoud of succesvolle aanmaakresponse.
3. Bereid het endpointresultaat voor zonder het al naar de client te schrijven. Ook resultaten uit middleware en de centrale exceptionafhandeling moeten dezelfde afronding gebruiken.
4. Rond de auditregel af vóór de response wordt gestart. Als deze write faalt, vervang de geplande response door HTTP 503 `audit_unavailable`. Een response mag niet eerst starten waarna auditregistratie pas in `finally` gebeurt.
5. Deel een database-transactie tussen de afronding en de bijbehorende wijziging aan secrets waar die wijziging een mutatie is. Bij een mislukte auditwrite worden zulke mutaties niet gecommit. Neem ook bestaande unlockattempt-reservering en reset expliciet mee: verzwak de beveiligingslimieten niet en registreer toegestane/mislukte pogingen voordat een bijbehorende wijziging wordt gecommit.
6. Gebruik voor korte afronding na clientdisconnect een begrensde server-side timeout die niet uitsluitend afhankelijk is van `RequestAborted`. Blokkeer niet onbeperkt op een auditwrite. Er is geen stille fallback naar alleen een applicatielog.

### Blobs en onomkeerbare gevolgen

PostgreSQL en de bestandopslag vormen geen gezamenlijke transactie. De implementatie moet dit expliciet afhandelen; een foutresponse achteraf maakt een reeds verwijderd bestand niet terug.

- **Aanmaken:** schrijf blobs als voorbereiding; publiceer de secretrecord en de geslaagde audituitkomst in één database-transactie. Bij een fout mogen voorbereide blobs geen bereikbaar secret vormen en moeten ze worden opgeruimd via de bestaande opruim-/reconciliatiemogelijkheden.
- **Lezen/openen/unlocken:** lees en prepareer inhoud, maar geef die pas vrij nadat de auditafronding is gecommit. Een auditfout geeft dus nooit een succesvolle inhoudresponse.
- **Intrekken:** voer geen onomkeerbare blobverwijdering uit vóórdat de benodigde auditwrites kunnen slagen. De gekozen verwijderaanpak moet de secretmutatie en audituitkomst consistent houden, bijvoorbeeld door blobs tijdelijk herstelbaar te verplaatsen en bij een transactiefout terug te zetten. Een duurzame verwijderopdracht is een alternatief, maar vereist expliciet herstelbare cleanup. Alleen bestaande blobs verwijderen en daarna proberen te loggen voldoet niet.

De implementatie mag hiervoor geen oneindige lock op een secretrecord vasthouden. Test failures op de grenzen tussen audit, secretmutatie en blobopslag afzonderlijk.

### Crashes, afgebroken requests en schrijffouten

Een procescrash of database-uitval kan een regel met `state=started` achterlaten. Dat is een zichtbaar onvolledig request, geen fictief succes. Als de initiële insert zelf onmogelijk is, kan er uiteraard geen auditregel voor die storing bestaan: het request faalt zonder uitvoering en de operationele logs bevatten de storingsmelding en servercorrelatie.

Als een finishwrite faalt, blijft de al geschreven beginregel beschikbaar. Als de database vervolgens weer bereikbaar is binnen de begrensde afronding, kan dezelfde regel worden afgesloten met `outcome=error`, `error_code=audit_unavailable` en HTTP 503. Interne retries gebruiken dezelfde `request_id`. Als dat niet lukt, blijft de regel onvolledig.

Een HTTP-status beschrijft de serveruitkomst, niet of alle bytes de ontvanger bereikten. Na de auditcommit kan de netwerkverbinding alsnog wegvallen. Clientdisconnects die vóór afronding worden waargenomen krijgen waar mogelijk `state=aborted`; verzin geen HTTP 499 die niet daadwerkelijk naar de client is gestuurd. Een automatische hersteltaak voor onafgeronde regels valt buiten deze fase.

## Verwijderen van de oude statistiekverzameling

Verwijder in de implementatie:

- `StatisticsEvent`, `StatisticsRecorder`, `StatisticsFinalizer` en `StatisticsDayFinalizedException`, inclusief DI-registratie, dagfinalisatie, statistieklocks en write-/error-hooks.
- Statistiekparameters en de verzameling van meerdere dagstatistieken in secretendpoints en repository-interfaces.
- De live uitleescode en het oude responsecontract voor dagtotalen.
- `Analytics:Key`, de bijbehorende file-secretverwerking, productievalidatie en Compose-/omgevingsconfiguratie, zodra deze nergens anders wordt gebruikt.
- De oude tabellen `stats_daily` en `stats_visitors_daily`, inclusief hun gegevens, via een nieuwe geversioneerde migratie.

Reguliere operationele logs blijven bestaan. Eventuele gedeelde IP-/keyhelpers die nu toevallig in `StatisticsRecorder` staan, worden verplaatst naar een onafhankelijke helper. `Security:AuditHashKey` blijft behouden zolang de bestaande diagnostische auditlogs deze gebruiken; verwar deze sleutel niet met de te verwijderen analyticssleutel. Dubbele operationele meldingen mogen geen dubbele database-auditregels opleveren.

Nieuwe statistiekberekeningen en de materialized view vallen buiten scope. Om geen kapotte oude statsflow te laten staan, vervalt de huidige aggregatieaanroep. Tijdelijk toont `/stats` alleen dat statistieken nog niet beschikbaar zijn, zonder API-oproep of oude meetdefinities. `/api/v1/stats` retourneert een expliciete HTTP 410 met `code=statistics_retired` en leest geen tabel. De nieuwe statsfeature kan dit contract later opnieuw ontwerpen.

## Migratie en compatibiliteit

Voeg een migratie na de huidige migratie 5 toe. Bewaar de bestaande migratiehistorie; wijzig reeds toegepaste migraties niet achteraf. Een verse database mag de bestaande migraties doorlopen waarna de nieuwe migratie de audit toevoegt en de oude tabellen verwijdert.

De migratie:

1. Maakt de audittabel, constraints en indexen aan.
2. Verwijdert alleen de oude statistiektabellen en hun gegevens.
3. Wijzigt of verwijdert geen bestaande secrets, ciphertextblobs, passwordgegevens, revokegegevens, expirydata of unlockattemptgegevens.
4. Voegt geen fictieve historische auditregels toe.

Voorkom dat een oude applicatie-instantie na het droppen van de tabellen nog statistieken schrijft. Gebruik een gecoördineerde overgang met alle oude instanties gestopt, of splits de destructieve migratie af totdat alle writers zijn vervangen. De overgang mag actieve secrets niet resetten. Het terugzetten van oude applicatiecode vereist expliciet herstel van het oude schema; verwijderde statistiekhistorie wordt niet vanzelf teruggebracht.

Het in-memory ontwikkel-/testpad krijgt een gelijkwaardige auditrepository met dezelfde registratie- en faalsemantiek. In productie blijven auditregels duurzaam in PostgreSQL opgeslagen. Onbeperkte retentie in productie betekent niet dat in-memory testgegevens een herstart moeten overleven.

## Documentatie en gebruikersinformatie

Werk bij implementatie README, runbook, configuratievoorbeelden en de Nederlandse en Engelse privacy-/beveiligingsteksten bij. Beschrijf expliciet dat secretrequesthistorie, secret-ID's, leesbare IP-adressen en toegestane metadata onbeperkt blijven bestaan na verwijdering van een secret. Uitspraken die raw-IP-opslag uitsluiten of alleen dagtotalen beschrijven, moeten worden aangepast.

De wijziging aan bewaring betreft trackingmetadata. Encryptie, wachtwoordbescherming, toegang, vervalduur en verwijdering van secretinhoud blijven functioneel behouden. Een nieuwe bezoekersstatistiek, dashboard, auditinzagescherm, export, materialized view of rapportagetaak hoort niet bij deze fase.

## Acceptatiecriteria en verificatie

1. Elk request binnen de scope maakt precies één regel met niet-null `secret_id`, ook bij metadata, afzonderlijke bestanden, verkeerd wachtwoord, rate limiting, origin-/HTTPS-afwijzing en onbekende/verwijderde secrets.
2. Elke aanmaakpoging krijgt vóór validatie en afwijzing een eigen secret-ID. Bij succesvolle aanmaak zijn dat ID, het opgeslagen secret-ID en het response-ID gelijk.
3. Malformed/mislukte aanmaak laat een auditregel maar geen actieve secretrecord achter. Verschillende HTTP-pogingen krijgen verschillende request-ID's; interne write-retries blijven bij één regel.
4. Een request naar een onbekend, ingetrokken of opgeruimd secret kan zonder FK-fout worden geregistreerd. Intrekken en expirycleanup laten bestaande auditregels intact.
5. Health-, capabilities- en algemene assetrequests maken geen auditregels. Een daadwerkelijke request naar de secretpagina en een bestandophaling wel.
6. IPv4 en IPv6 worden leesbaar opgeslagen. Een mapped IPv4-adres wordt genormaliseerd. Een onbetrouwbare forwardingheader verandert het geregistreerde client-IP niet.
7. Een mislukte initiële auditwrite geeft HTTP 503 en voert geen secretactie uit. Een mislukte afronding geeft geen succesresponse of inhoud vrij. Database-mutaties worden teruggedraaid; blobmutaties hebben geteste compensatie of duurzame cleanup.
8. Test specifiek intrekken bij audituitval: een failed auditcommit mag geen ongeregistreerde, onomkeerbare intrekking achterlaten. Test ook failure/cancellation tijdens unlockattempt-reservering en reset zonder de bestaande limieten te omzeilen.
9. Clientdisconnects en procesonderbrekingen worden niet als gegarandeerd afgeleverd succes weergegeven. Onafgeronde regels blijven herkenbaar.
10. Contextvelden bevatten alleen de afgesproken metadata. Test met herkenbare geheime waarden dat bodies, tokens, keys, namen en inhoud niet in de audit terechtkomen.
11. De migratie werkt zowel op een verse database als op een database met bestaande secrets en oude stats. Oude stats verdwijnen; bestaande beschermde en onbeschermde secrets met bericht/bestanden blijven opvraagbaar, ontgrendelbaar en intrekbaar.
12. Er is geen achtergrondproces, daglock, IP-HMAC-verzameling of actieve schrijf-/leesroute voor de oude statistieken over. Diagnostische logs en rate limiting blijven functioneren.
13. De tijdelijke statsroute toont geen oude cijfers en geen ruwe auditgegevens. Er wordt geen materialized view of nieuwe statistiekberekening toegevoegd.
14. Controleer de tests en documentatie op achtergebleven aannames over IP-HMAC-statistieken en auditfouten die genegeerd mogen worden. Voer de bestaande secretflow-, unlockbeveiligings- en relevante frontendcontroles uit naast de nieuwe audit-/migratie-integratietests.

De oplevering van deze fase is een werkende requestaudit, verwijdering van de oude statsverzameling en bijgewerkte documentatie. Nieuwe rapportage volgt afzonderlijk.
