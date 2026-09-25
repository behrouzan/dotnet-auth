# Behrouzan.Auth.AspNetCore

`Behrouzan.Auth.AspNetCore` integrates the core library with ASP.NET Core and ASP.NET Core Identity. It provides permission-authorization policy support, a user-ID resolver, password sign-in orchestration, access-JWT creation, and token login/refresh orchestration.

It depends on `Behrouzan.Auth`. It does not provide EF Core storage; use `Behrouzan.Auth.EntityFrameworkCore` or register your own core storage interfaces. It also does not configure a bearer handler, validate JWTs, choose a signing algorithm/key, expose HTTP endpoints, or implement antiforgery policy. Those responsibilities remain with the consuming application.

## Minimal Identity and password-sign-in registration

```csharp
using Behrouzan.Auth.AspNetCore.Authentication;
using Behrouzan.Auth.AspNetCore.DependencyInjection;

builder.Services.AddAuthorization();
builder.Services.AddBehrouzanAuthAspNetCore<Guid>();
builder.Services.AddBehrouzanPasswordSignIn<ApplicationUser>(options =>
    options.AllowedIdentifiers =
        SignInIdentifier.UserName | SignInIdentifier.Email);
```

The application must already configure ASP.NET Core Identity and its authentication schemes. After `var app = builder.Build()`, add `app.UseAuthentication()` and `app.UseAuthorization()` before mapping protected endpoints. Inject `PasswordSignInManager<ApplicationUser>` into an application endpoint and call `SignInAsync(identifier, password, isPersistent, cancellationToken)`; Identity owns the resulting application-cookie sign-in.

## Token registration outline

The following registrations use existing API, but the application must supply the interfaces, refresh-token persistence, and bearer validation policy shown below. A complete runnable reference is [Sample.Api's registration](https://github.com/behrouzan/dotnet-auth/blob/main/samples/Sample.Api/Program.cs).

```csharp
using Behrouzan.Auth.AspNetCore.Authentication;
using Behrouzan.Auth.AspNetCore.DependencyInjection;
using Behrouzan.Auth.Authentication;
using Behrouzan.Auth.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

builder.Services.AddAuthentication().AddJwtBearer(
    JwtBearerDefaults.AuthenticationScheme,
    options => options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = signingKey,
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        ValidateLifetime = true
    });

builder.Services.AddBehrouzanAccessTokens(options =>
{
    options.Issuer = issuer;
    options.Audience = audience;
    options.Lifetime = TimeSpan.FromMinutes(15);
});
builder.Services.AddBehrouzanIdentityTokenLogin<ApplicationUser, Guid>();
builder.Services.AddBehrouzanTokenRefresh<ApplicationUser, Guid>();
builder.Services.AddRefreshTokens(options =>
    options.Lifetime = TimeSpan.FromDays(14));
builder.Services.AddScoped<IRefreshTokenStore<Guid>, ApplicationRefreshTokenStore>();
builder.Services.AddSingleton<IAccessTokenSigningCredentialsProvider>(
    new ApplicationSigningCredentialsProvider(signingKey));
builder.Services.AddScoped<IRefreshTokenUserResolver<ApplicationUser, Guid>,
    ApplicationRefreshTokenUserResolver>();
```

Here `issuer`, `audience`, and `signingKey` are application configuration, `ApplicationSigningCredentialsProvider` implements `IAccessTokenSigningCredentialsProvider`, `ApplicationRefreshTokenUserResolver` implements `IRefreshTokenUserResolver<ApplicationUser, Guid>`, and `ApplicationRefreshTokenStore` implements `IRefreshTokenStore<Guid>`. `AddRefreshTokens(...)` and that store registration are required for `TokenLoginManager` and `TokenRefreshManager`; the registrations above alone are insufficient. `AddBehrouzanIdentityTokenLogin` supplies the standard resolver only for an `IdentityUser<TKey>`-based user; applications with another user model use `AddBehrouzanTokenLogin` and register `ITokenUserIdentityResolver<TUser, TKey>` themselves.

## Security and flow limits

- Token login and refresh return `RequiresTwoFactor` when Identity requires 2FA. This package does not complete a token-based 2FA flow or issue tokens before that factor is satisfied.
- Signing access JWTs and validating bearer JWTs are consuming-application responsibilities; configure compatible issuer, audience, algorithm, and key policy on both sides.
- Refresh-token logout prevents subsequent refreshes, but an already-issued access JWT remains valid until its configured expiration. Security-stamp changes do not automatically revoke refresh tokens.
- For user-wide logout, invoke `IRefreshTokenManager<TKey>.RevokeAllAsync` with a trusted authenticated user ID.

Detailed repository guidance:

- https://github.com/behrouzan/dotnet-auth/blob/main/docs/getting-started.md
- https://github.com/behrouzan/dotnet-auth/blob/main/docs/authentication-flows.md
- https://github.com/behrouzan/dotnet-auth/blob/main/docs/security-and-data.md

No published package version, installation command, or license is asserted by this README.
