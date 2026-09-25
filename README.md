# Behrouzan.Auth

`Behrouzan.Auth` is a .NET 8 library set for ASP.NET Core Identity applications. It currently provides permission checks and grants, password sign-in helpers, refresh-token persistence and rotation, and JWT access-token issuance. It is pre-release source code: package publication, stable package versions, and production compatibility guarantees have not been announced.

| Project | Responsibility | Dependencies supplied by this repository |
| --- | --- | --- |
| `Behrouzan.Auth` | Core permission and refresh-token abstractions, managers, options, and DI registrations. | Depends on `Behrouzan.Results`, `Microsoft.Extensions.DependencyInjection.Abstractions`, and `Microsoft.Extensions.Options`. It does not persist tokens or configure ASP.NET Core authentication. |
| `Behrouzan.Auth.AspNetCore` | ASP.NET Core authorization integration, Identity-based password sign-in, token login/refresh orchestration, and JWT issuance. | References `Behrouzan.Auth`, `Microsoft.AspNetCore.App`, and `System.IdentityModel.Tokens.Jwt`. The application supplies JWT validation, signing credentials, and endpoints. |
| `Behrouzan.Auth.EntityFrameworkCore` | EF Core implementations for refresh-token and permission-grant storage, identifier lookup, and model configuration. | References `Behrouzan.Auth`, `Microsoft.AspNetCore.Identity.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore`, and `Microsoft.EntityFrameworkCore.Relational`. It requires an Identity EF Core context. |

The repository also contains `samples/Sample.Api`, an executable reference for cookie and JWT bearer authentication. It uses project references, not published NuGet packages; installation commands and package versions are intentionally not documented until a release exists.

## Current capabilities

- Password sign-in with username, email, and/or phone-number selection.
- Cookie sign-in through ASP.NET Core Identity (the application owns its endpoints and antiforgery policy).
- JWT access-token creation from an application-provided signing-credentials provider.
- Opaque, hashed refresh tokens with expiration, rotation, reuse detection, one-session revocation, and user-wide revocation.
- Permission definitions, role grants, permission evaluation through Identity role membership, and ASP.NET Core permission authorization attributes.
- EF Core model and store support for Identity-based user and role types.

## Guides

- [Getting started](docs/getting-started.md)
- [Authentication flows](docs/authentication-flows.md)
- [Security and data considerations](docs/security-and-data.md)
- [Refresh-token `ExpiresAt` storage upgrade](docs/refresh-token-storage-upgrade.md)
- [Sample.Api](samples/Sample.Api/README.md)
