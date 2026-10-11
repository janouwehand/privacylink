# Advies: verantwoordelijkheden van PrivacyLink.Api

## Kort oordeel

De richting is goed: `PrivacyLink.Api` hoort vooral de HTTP-ingang en de composition root te zijn. Een `PrivacyLink.Services`-assembly past als die use-cases en applicatiecoördinatie bevat. Verplaats echter niet automatisch “vrijwel alle functionaliteit” daarheen: Microsofts richtlijnen scheiden juist applicatie/businesslogica, transport en infrastructuur. De projectgrenzen zijn een middel om die verantwoordelijkheden en afhankelijkheden af te dwingen, geen doel op zichzelf. [Microsoft: architectuurprincipes](https://learn.microsoft.com/en-us/dotnet/architecture/modern-web-apps-azure/architectural-principles) · [Microsoft: common web application architectures](https://learn.microsoft.com/en-us/dotnet/architecture/modern-web-apps-azure/common-web-application-architectures)

## Huidige situatie

De solution heeft `PrivacyLink.Api` en `PrivacyLink.Contracts`. In `Api` zitten nu zowel de HTTP-routes en hostconfiguratie als de secret-use-cases (`SecretEndpoints`), opslaginterfaces en opslagimplementaties (`Persistence`), password-envelope-logica, opruimtaken en audit-/configuratiecode. De API-csproj bevat ook de Npgsql- en Argon2-package references. Dit maakt de API verantwoordelijk voor meerdere soorten werk, en maakt het lastig om use-cases los van ASP.NET en concrete opslag te testen.

## Aanbevolen grenzen

| Project | Verantwoordelijkheid | Voorbeelden uit de huidige code |
| --- | --- | --- |
| `PrivacyLink.Api` | HTTP/ASP.NET Core, transportmapping, middleware, hostconfiguratie en dependency-injection composition root | `Program.cs`, route-endpoints, HTTP-rate limiting, forwarded headers, response- en requestmapping |
| `PrivacyLink.Services` | Use-cases, toepassingscoördinatie, applicatievalidatie en poortinterfaces die use-cases nodig hebben | Secret aanmaken/openen/unlocken/revoken; interfaces voor secret- en blob-opslag; applicatieresultaten |
| `PrivacyLink.Infrastructure` (aanbevolen zodra opslag uit de API wordt gehaald) | Concrete adapters en externe technologieën | PostgreSQL/Npgsql-repository, bestand- en in-memory blobopslag, schema/migraties en opslaginitialisatie |
| `PrivacyLink.Contracts` | Publieke/wire-contracten voor clients, als die door client en API gedeeld worden | Huidige request- en response-records |

Laat `Api` de HTTP-request vertalen naar een service-input en het resultaat naar een HTTP-status/contract. Houd `HttpRequest`, `IResult`, ASP.NET-validatiemodellen en `IConfiguration` buiten de use-cases. Een service coördineert opslag en domeinobjecten; bedrijfsregels/invarianten horen bij het domein, niet in routes of opslagimplementaties. Microsoft beschrijft de application layer als dunne use-casecoördinatie en infrastructuur als implementatie van opslag en andere technische diensten. [Microsoft: DDD-georiënteerde service](https://learn.microsoft.com/en-us/dotnet/architecture/microservices/microservice-ddd-cqrs-patterns/ddd-oriented-microservice) · [Microsoft: tactical DDD](https://learn.microsoft.com/en-us/azure/architecture/microservices/model/tactical-domain-driven-design)

## Afhankelijkheden

Richt compile-time afhankelijkheden naar de kern: `Api → Services`, `Infrastructure → Services`; alleen de composition root in `Api` hoeft concrete infrastructuur te kennen voor DI-registratie. `Services` kent de opslagabstractions, maar niet Npgsql, filesystem-implementaties of ASP.NET. Zo kan infrastructuur tegen de service-abstractions programmeren en kunnen use-cases geïsoleerd worden getest. Microsoft beschrijft dit als dependency inversion; de UI-laag kan in de composition root de infrastructuurregistratie doen. [Microsoft: Clean Architecture en projectgrenzen](https://learn.microsoft.com/en-us/dotnet/architecture/modern-web-apps-azure/common-web-application-architectures#clean-architecture)

```text
PrivacyLink.Api ───────► PrivacyLink.Services ◄─────── PrivacyLink.Infrastructure
       └────────────────► PrivacyLink.Infrastructure
       composition root registreert de implementaties
```

`PrivacyLink.Contracts` is een randgeval: als dit wire-formaten zijn die alleen API en client delen, laat Services dan eigen use-case-inputs/-outputs hebben en map tussen die modellen. Zo wordt het applicatiemodel niet gekoppeld aan het HTTP-contract. Als contracten bewust frameworkonafhankelijk en intern gedeeld zijn, kan Services ernaar verwijzen, maar voorkom een circulaire projectreferentie.

## Praktisch advies voor PrivacyLink

1. Maak `PrivacyLink.Services` voor use-cases en hun interfaces. Verplaats de applicatiecoördinatie uit `SecretEndpoints`; behoud daar alleen HTTP-binding, protocol-/transportchecks en responsemapping.
2. Haal concrete opslag uit `Persistence.cs` naar `PrivacyLink.Infrastructure`; verplaats Npgsql als package reference mee. Behoud opslagabstractions bij Services.
3. Houd ASP.NET-hostbeleid in Api, waaronder headers/middleware, forwarded headers, rate limiting en routeconfiguratie. Beoordeel per regel of het HTTP-beleid is of een use-casebeperking.
4. Verplaats hosted workers naar het project dat hun verantwoordelijkheid bezit: opslaginitialisatie/opruiming bij Infrastructure wanneer ze opslag beheren; registreer ze vanuit de Api composition root. Houd domain- en toepassingsregels in Services.
5. Begin zonder extra `Domain`-project als de domeinlogica klein is. Splits dat pas af wanneer domeinregels en model een duidelijke, zelfstandig testbare kern vormen. Microsoft noemt eenvoudige CRUD-systemen expliciet als geschikt voor een eenvoudiger ontwerp. [Microsoft: DDD-georiënteerde service](https://learn.microsoft.com/en-us/dotnet/architecture/microservices/microservice-ddd-cqrs-patterns/ddd-oriented-microservice)

**Conclusie:** `PrivacyLink.Services` is een bruikbare naam en stap, mits het een gerichte application/use-case-laag wordt. Voor de huidige code is de nuttige scheiding minstens `Api` / `Services` / `Infrastructure`; “bijna alle functionaliteit” in Services zou alleen de huidige grote API-assembly vervangen door een nieuwe verzamel-assembly.
