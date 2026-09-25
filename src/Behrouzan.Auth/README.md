# Behrouzan.Auth

Prepared for preview release `0.1.0-preview.1` under the MIT license:

```shell
dotnet add package Behrouzan.Auth --version 0.1.0-preview.1
```

The command becomes usable from nuget.org after this version is published; this README does not assert that the push has already occurred.

`Behrouzan.Auth` is the framework-neutral core package. It provides permission-definition and role-grant abstractions, refresh-token abstractions and lifecycle management, option types, and dependency-injection registrations.

It does not configure ASP.NET Core authentication, issue or validate JWTs, persist refresh tokens, or supply an Identity/EF Core implementation. The application must register implementations of the storage interfaces it uses, such as `IRefreshTokenStore<TKey>`, `IPermissionGrantStore<TKey>`, and `IRolePermissionGrantStore<TKey>`.

## Relationship to the other packages

This is the base package. `Behrouzan.Auth.AspNetCore` and `Behrouzan.Auth.EntityFrameworkCore` both depend on it. Neither package is required when an application supplies its own ASP.NET Core integration or persistence implementation.

## Minimal registration

```csharp
using Behrouzan.Auth.Authentication;
using Behrouzan.Auth.DependencyInjection;
using Behrouzan.Auth.Permissions;

builder.Services.AddBehrouzanAuth();
builder.Services.AddRefreshTokens(options =>
    options.Lifetime = TimeSpan.FromDays(14));

// Application-provided persistence implementations.
builder.Services.AddScoped<IRefreshTokenStore<Guid>, ApplicationRefreshTokenStore>();
builder.Services.AddScoped<IPermissionGrantStore<Guid>, ApplicationPermissionGrantStore>();
builder.Services.AddScoped<IRolePermissionGrantStore<Guid>, ApplicationRolePermissionGrantStore>();
```

`AddRefreshTokens` validates that the lifetime is positive and registers `IRefreshTokenManager<TKey>`. The example's three `Application...Store` types are application implementations of the corresponding interfaces; the core package does not include them.

## Permission and refresh-token use

After an application defines and registers its permission provider, it can manage a role's defined permissions and check a user's effective permissions:

```csharp
var grant = await rolePermissionManager.GrantAsync(
    administratorRoleId,
    "Products.Create",
    cancellationToken);

if (!grant.IsSuccess)
    return grant.ErrorCode; // UnknownPermission when the name was not defined.

var canCreate = await permissionChecker.IsGrantedAsync(
    userId,
    "Products.Create",
    cancellationToken);
```

`RolePermissionManager<TKey>` stores grants against roles. Whether `canCreate` is true depends on the application's `IPermissionGrantStore<TKey>` implementation; the EF Core implementation derives it from the user's Identity role memberships.

The refresh-token manager returns result objects rather than throwing for ordinary invalid-token outcomes:

```csharp
var created = await refreshTokenManager.CreateAsync(userId, cancellationToken);
if (created.IsSuccess)
{
    var renewal = await refreshTokenManager.RefreshAsync(
        created.Token!, cancellationToken);

    // A failed renewal reports InvalidToken, Expired, Revoked,
    // ReuseDetected, or ConcurrencyConflict through ErrorCode.
}
```

After registration, an application can inject `IRefreshTokenManager<Guid>` and use `CreateAsync`, `ValidateAsync`, `RefreshAsync`, `RevokeAsync`, and `RevokeAllAsync`. Treat a raw refresh token as a credential: return it only to its owner and never persist it in plaintext.

For permission definitions, role-grant management, and user permission checks, see the [Permissions guide](https://github.com/behrouzan/dotnet-auth/blob/main/docs/permissions.md). Permissions are granted to roles; direct user permission grants are not provided.

## Important limits

- Revoking a refresh token does not immediately invalidate an already-issued access JWT.
- `RevokeAllAsync` revokes active refresh tokens for a trusted user ID; callers must derive that ID from an authenticated identity, not request input.
- Security-stamp changes do not automatically revoke refresh tokens.
- Concurrency behavior is determined in part by the storage implementation and database provider.

The repository's detailed guidance is available at:

- https://github.com/behrouzan/dotnet-auth/blob/main/docs/authentication-flows.md
- https://github.com/behrouzan/dotnet-auth/blob/main/docs/security-and-data.md
- https://github.com/behrouzan/dotnet-auth/blob/main/docs/refresh-token-storage-upgrade.md
