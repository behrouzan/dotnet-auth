# Getting started

This guide covers the packages prepared for the `0.1.0-preview.1` release. The commands below become usable from nuget.org after the preview is pushed; publication is not asserted here. The complete working source reference is [Sample.Api](../samples/Sample.Api/README.md).

## Install the preview packages

Install the packages needed for your application:

```shell
dotnet add package Behrouzan.Auth --version 0.1.0-preview.1
dotnet add package Behrouzan.Auth.AspNetCore --version 0.1.0-preview.1
dotnet add package Behrouzan.Auth.EntityFrameworkCore --version 0.1.0-preview.1
```

`Behrouzan.Auth.AspNetCore` and `Behrouzan.Auth.EntityFrameworkCore` each install the matching `Behrouzan.Auth` dependency automatically. Installing that dependency does not enable the other package's capabilities: register and configure the Core, ASP.NET Core, and EF Core services required by the application as shown below. The packages are licensed under MIT.

## Prerequisites

Use .NET 8, ASP.NET Core Identity, and an EF Core context derived from `IdentityDbContext<TUser, TRole, TKey>`. The EF integration's generic constraints require `TUser : IdentityUser<TKey>`, `TRole : IdentityRole<TKey>`, and `TKey : IEquatable<TKey>`.

Configure the Behrouzan entities after the base Identity model:

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

Create and apply an EF Core migration for this model. If you already have refresh-token data from the earlier `ExpiresAt` mapping, follow the dedicated [storage-upgrade guide](refresh-token-storage-upgrade.md), rather than applying a type-only migration.

## Register Identity, storage, and library services

The following registration uses SQLite, as the sample does. Selecting and configuring a database provider is still an application concern; replace `UseSqlite` when your application uses another provider. JWT validation and signing-key retrieval are also application concerns.

```csharp
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services
    .AddIdentity<ApplicationUser, ApplicationRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthorization();
builder.Services.AddBehrouzanAuth();
builder.Services.AddRefreshTokens(options =>
    options.Lifetime = TimeSpan.FromDays(14));
builder.Services.AddBehrouzanAuthAspNetCore<Guid>();
builder.Services.AddBehrouzanAuthEntityFrameworkCore<
    ApplicationDbContext, ApplicationUser, ApplicationRole, Guid>();
builder.Services.AddBehrouzanPasswordSignIn<ApplicationUser>(options =>
    options.AllowedIdentifiers = SignInIdentifier.UserName | SignInIdentifier.Email);
```

The namespaces for those extensions are `Behrouzan.Auth.DependencyInjection`, `Behrouzan.Auth.AspNetCore.DependencyInjection`, and `Behrouzan.Auth.EntityFrameworkCore.DependencyInjection`.

## Minimal cookie flow

Identity registers its application cookie. Configure the normal middleware and use `PasswordSignInManager<TUser>` in an endpoint after enforcing your chosen antiforgery policy:

```csharp
app.UseAuthentication();
app.UseAuthorization();

var result = await signInManager.SignInAsync(
    identifier, password, rememberMe, cancellationToken);
```

`PasswordSignInManager<TUser>.SignInAsync` delegates successful sign-in to Identity's application scheme. In the sample, its endpoint returns 204 on `IsSuccess`; it maps 2FA to 501 because the sample deliberately has no 2FA completion endpoint. See [Sample.Api's endpoint](../samples/Sample.Api/Endpoints/AuthEndpoints.cs).

## Minimal token flow

The following is a service-registration outline, not a copy-and-run example: `issuer`, `audience`, and `signingKey` must come from application configuration, and the two application-specific implementations must be supplied. For a complete compiling implementation, use [Sample.Api's registrations](../samples/Sample.Api/Program.cs), [options parser](../samples/Sample.Api/TokenAuthentication/SampleTokenAuthenticationOptions.cs), [signing-credentials provider](../samples/Sample.Api/TokenAuthentication/SampleAccessTokenSigningCredentialsProvider.cs), and [refresh-token user resolver](../samples/Sample.Api/TokenAuthentication/ApplicationRefreshTokenUserResolver.cs).

```csharp
builder.Services.AddAuthentication().AddJwtBearer(
    JwtBearerDefaults.AuthenticationScheme,
    options => options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true, ValidIssuer = issuer,
        ValidateAudience = true, ValidAudience = audience,
        ValidateIssuerSigningKey = true, IssuerSigningKey = signingKey,
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        ValidateLifetime = true, ClockSkew = TimeSpan.Zero,
        NameClaimType = "sub"
    });

builder.Services.AddBehrouzanAccessTokens(options =>
{
    options.Issuer = issuer;
    options.Audience = audience;
    options.Lifetime = TimeSpan.FromMinutes(15);
});
builder.Services.AddBehrouzanIdentityTokenLogin<ApplicationUser, Guid>();
builder.Services.AddBehrouzanTokenRefresh<ApplicationUser, Guid>();
builder.Services.AddSingleton<IAccessTokenSigningCredentialsProvider>(
    new ApplicationAccessTokenSigningCredentialsProvider(signingKey));
builder.Services.AddScoped<IRefreshTokenUserResolver<ApplicationUser, Guid>,
    ApplicationRefreshTokenUserResolver>();
```

`ApplicationAccessTokenSigningCredentialsProvider` represents an application implementation of `IAccessTokenSigningCredentialsProvider`; `ApplicationRefreshTokenUserResolver` represents one of `IRefreshTokenUserResolver<ApplicationUser, Guid>`. The corresponding concrete Sample.Api types are linked above.

Call `TokenLoginManager<ApplicationUser, Guid>.LoginAsync` and `TokenRefreshManager<ApplicationUser, Guid>.RefreshAsync` from application endpoints; return the resulting access token, expiration, and refresh token only on `IsSuccess`. See [authentication flows](authentication-flows.md) for outcome handling.
