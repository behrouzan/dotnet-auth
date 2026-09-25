# Behrouzan.Auth.EntityFrameworkCore

`Behrouzan.Auth.EntityFrameworkCore` provides Entity Framework Core storage for the core package: refresh-token persistence, role-permission grants, role-grant lookup, phone-number user lookup, and model configuration.

It depends on `Behrouzan.Auth` and requires an Identity EF Core model. It does not configure a database provider, create or apply migrations, configure ASP.NET Core authentication, issue JWTs, or expose endpoints. The consuming application owns those concerns.

## Identity and model requirements

The DI and model APIs require a context derived from `IdentityDbContext<TUser, TRole, TKey>`, where `TUser : IdentityUser<TKey>`, `TRole : IdentityRole<TKey>`, and `TKey : IEquatable<TKey>`.

```csharp
using Behrouzan.Auth.EntityFrameworkCore.Extensions;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public sealed class ApplicationDbContext
    : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.ConfigureBehrouzanAuth<ApplicationUser, ApplicationRole, Guid>();
    }
}
```

Call the extension after `base.OnModelCreating`. It configures the refresh-token and role-permission-grant entities; generate and apply migrations with the application's selected EF Core provider.

## Minimal registration

```csharp
using Behrouzan.Auth.EntityFrameworkCore.DependencyInjection;
using Microsoft.EntityFrameworkCore;

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddBehrouzanAuthEntityFrameworkCore<
    ApplicationDbContext,
    ApplicationUser,
    ApplicationRole,
    Guid>();
```

This registers the EF implementations of `IRefreshTokenStore<TKey>`, `IPermissionGrantStore<TKey>`, `IRolePermissionGrantStore<TKey>`, and `IUserIdentifierLookup<TUser>`. Register the core services separately with `AddBehrouzanAuth()` and `AddRefreshTokens(...)`; use the ASP.NET Core package separately if its integration is needed.

## `ExpiresAt` migration warning

Refresh-token `ExpiresAt` is mapped as UTC .NET ticks so that expiration comparison can be translated during conditional token rotation. Existing databases that used the earlier `DateTimeOffset` representation require a provider-specific, data-converting migration. Do not deploy a type-only `AlterColumn` migration; it can reinterpret existing values incorrectly.

For the full conversion and concurrency guidance, see:

- https://github.com/behrouzan/dotnet-auth/blob/main/docs/refresh-token-storage-upgrade.md
- https://github.com/behrouzan/dotnet-auth/blob/main/docs/security-and-data.md
- https://github.com/behrouzan/dotnet-auth/blob/main/docs/getting-started.md

No published package version, installation command, or license is asserted by this README.
