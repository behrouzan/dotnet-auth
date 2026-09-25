# Behrouzan.Auth

`Behrouzan.Auth` is a .NET 8 library set for ASP.NET Core Identity applications. It currently provides permission checks and grants, password sign-in helpers, refresh-token persistence and rotation, and JWT access-token issuance. The three packages are prepared for the first preview release, `0.1.0-preview.1`; preview APIs may change before a stable release.

| Project | Responsibility | Dependencies supplied by this repository |
| --- | --- | --- |
| `Behrouzan.Auth` | Core permission and refresh-token abstractions, managers, options, and DI registrations. | Depends on `Behrouzan.Results`, `Microsoft.Extensions.DependencyInjection.Abstractions`, and `Microsoft.Extensions.Options`. It does not persist tokens or configure ASP.NET Core authentication. |
| `Behrouzan.Auth.AspNetCore` | ASP.NET Core authorization integration, Identity-based password sign-in, token login/refresh orchestration, and JWT issuance. | References `Behrouzan.Auth`, `Microsoft.AspNetCore.App`, and `System.IdentityModel.Tokens.Jwt`. The application supplies JWT validation, signing credentials, and endpoints. |
| `Behrouzan.Auth.EntityFrameworkCore` | EF Core implementations for refresh-token and permission-grant storage, identifier lookup, and model configuration. | References `Behrouzan.Auth`, `Microsoft.AspNetCore.Identity.EntityFrameworkCore`, `Microsoft.EntityFrameworkCore`, and `Microsoft.EntityFrameworkCore.Relational`. It requires an Identity EF Core context. |

The repository also contains `samples/Sample.Api`, an executable reference for cookie and JWT bearer authentication. It uses project references so that it exercises the source in this repository.

## Preview package installation

The following commands target the packages prepared for `0.1.0-preview.1`. They become usable from nuget.org after that version is pushed; this repository does not claim that publication has already occurred.

```shell
dotnet add package Behrouzan.Auth --version 0.1.0-preview.1
dotnet add package Behrouzan.Auth.AspNetCore --version 0.1.0-preview.1
dotnet add package Behrouzan.Auth.EntityFrameworkCore --version 0.1.0-preview.1
```

Install only the packages needed by the application. The ASP.NET Core and EF Core packages each bring `Behrouzan.Auth` as a dependency, but their features still require their own service registration and application-owned configuration. All three packages use the MIT license.

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
- [Permissions](docs/permissions.md)
- [Refresh-token `ExpiresAt` storage upgrade](docs/refresh-token-storage-upgrade.md)
- [Sample.Api](samples/Sample.Api/README.md)
