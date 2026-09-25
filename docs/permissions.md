# Permissions

This guide shows the permission path implemented by the current public API: define permissions, grant them to roles, resolve a user's role-derived permissions, and protect ASP.NET Core controller actions. It uses `Guid` keys; use the same key type consistently for your Identity user, Identity role, context, managers, and checkers.

`Sample.Api` currently demonstrates cookie and token authentication, but does not expose a permission-protected endpoint. The examples below are an integration outline assembled from the public API and the repository's permission tests, not code copied from Sample.Api.

## 1. Define groups and permissions

Create one or more `PermissionDefinitionProvider` implementations. Permission names must be unique across all registered providers.

```csharp
using Behrouzan.Auth.Permissions;

public static class ProductPermissions
{
    public const string View = "Products.View";
    public const string Create = "Products.Create";
    public const string Edit = "Products.Edit";
}

public sealed class ProductPermissionProvider : PermissionDefinitionProvider
{
    public override void Define(IPermissionDefinitionContext context)
    {
        var products = context.AddGroup("Products", "Products");

        products.AddPermission(ProductPermissions.View, "View products");
        products.AddPermission(ProductPermissions.Create, "Create products");
        products.AddPermission(ProductPermissions.Edit, "Edit products");
    }
}
```

## 2. Register core, ASP.NET Core, and EF Core services

The EF Core integration requires `ApplicationDbContext` to derive from `IdentityDbContext<ApplicationUser, ApplicationRole, Guid>`. In `OnModelCreating`, call `base.OnModelCreating(builder)` and then `builder.ConfigureBehrouzanAuth<ApplicationUser, ApplicationRole, Guid>()`; see the [getting-started guide](getting-started.md) for the complete model outline.

```csharp
using Behrouzan.Auth.AspNetCore.DependencyInjection;
using Behrouzan.Auth.DependencyInjection;
using Behrouzan.Auth.EntityFrameworkCore.DependencyInjection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services
    .AddIdentity<ApplicationUser, ApplicationRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.AddAuthorization();
builder.Services.AddBehrouzanAuth();
builder.Services.AddPermissionDefinition<ProductPermissionProvider>();
builder.Services.AddBehrouzanAuthAspNetCore<Guid>();
builder.Services.AddBehrouzanAuthEntityFrameworkCore<
    ApplicationDbContext,
    ApplicationUser,
    ApplicationRole,
    Guid>();
```

`AddBehrouzanAuth()` registers `RolePermissionManager<TKey>` and `IPermissionChecker<TKey>`. `AddBehrouzanAuthEntityFrameworkCore` registers the EF stores used by both. `AddBehrouzanAuthAspNetCore<Guid>()` registers the authorization handler and dynamic policy provider used by the attributes below.

The default ASP.NET Core `IUserIdResolver<Guid>` reads `ClaimTypes.NameIdentifier`. That works with the usual Identity cookie principal. If a bearer scheme exposes the user ID only as JWT `sub`, as Sample.Api does with `MapInboundClaims = false`, register an application `IUserIdResolver<Guid>` that resolves that claim instead.

After `var app = builder.Build()`, call `app.UseAuthentication()` and `app.UseAuthorization()` before mapping protected endpoints.

## 3. Manage a role's permissions

Inject `RolePermissionManager<Guid>` into an application service or administrative controller. Every name passed to grant, revoke, or set must have been defined by a registered provider; otherwise the operation returns `PermissionManagementErrorCode.UnknownPermission` and does not change the store.

```csharp
using Behrouzan.Auth.Permissions;

var grant = await rolePermissionManager.GrantAsync(
    administratorRoleId,
    ProductPermissions.Create,
    cancellationToken);

var current = await rolePermissionManager.GetPermissionsAsync(
    administratorRoleId,
    cancellationToken);

var replace = await rolePermissionManager.SetPermissionsAsync(
    administratorRoleId,
    [ProductPermissions.View, ProductPermissions.Edit],
    cancellationToken);

var revoke = await rolePermissionManager.RevokeAsync(
    administratorRoleId,
    ProductPermissions.Edit,
    cancellationToken);
```

Check `IsSuccess` and `ErrorCode` on each `PermissionManagementResult` before reporting success to a caller. `SetPermissionsAsync` replaces the full role permission set; passing an empty collection removes every permission from that role.

Granting a permission to a role does not grant it to users outside that role. The application must create roles with `RoleManager` and add each user to the intended role through ASP.NET Core Identity, for example `await userManager.AddToRoleAsync(user, "Administrators")`. Only then can the EF permission checker obtain that role's grants through the user's Identity role membership.

## 4. Check a user's permissions

Inject `IPermissionChecker<Guid>` where an imperative check is appropriate:

```csharp
var canCreate = await permissionChecker.IsGrantedAsync(
    currentUserId,
    ProductPermissions.Create,
    cancellationToken);

var canEditOrCreate = await permissionChecker.IsAnyGrantedAsync(
    currentUserId,
    [ProductPermissions.Edit, ProductPermissions.Create],
    cancellationToken);

var canViewAndEdit = await permissionChecker.AreAllGrantedAsync(
    currentUserId,
    [ProductPermissions.View, ProductPermissions.Edit],
    cancellationToken);
```

The EF implementation reads the user's `IdentityUserRole<TKey>` memberships, then reads matching rows from `BehrouzanRolePermissionGrants`. A grant is stored against a role, not directly against a user. A user's effective permissions are the distinct permissions granted by that user's roles; this package does not provide direct user permission grants.

## 5. Protect controller endpoints

For controller or action methods, the public attributes create authenticated permission policies. They are supported by `AddBehrouzanAuthAspNetCore<TKey>()` and use the same `IPermissionChecker<TKey>` described above.

```csharp
using Behrouzan.Auth.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("products")]
public sealed class ProductsController : ControllerBase
{
    [HttpGet]
    [RequirePermission(ProductPermissions.View)]
    public IActionResult Get() => Ok();

    [HttpPost]
    [RequireAnyPermission(
        ProductPermissions.Create,
        ProductPermissions.Edit)]
    public IActionResult Create() => Ok();

    [HttpPut("{id:guid}")]
    [RequireAllPermissions(
        ProductPermissions.View,
        ProductPermissions.Edit)]
    public IActionResult Update(Guid id) => NoContent();
}
```

This is a controller example: the application must also register controllers and map them (`AddControllers()` and `MapControllers()`). The attributes target classes and methods; their use on minimal-API delegates is not demonstrated by this API or its tests.

## Further reading and source references

- [Getting started](getting-started.md)
- [Behrouzan.Auth permission tests](https://github.com/behrouzan/dotnet-auth/blob/main/tests/Behrouzan.Auth.Tests/Permissions/RolePermissionManagerTests.cs)
- [ASP.NET Core authorization integration tests](https://github.com/behrouzan/dotnet-auth/blob/main/tests/Behrouzan.Auth.AspNetCore.Tests/Authorization/PermissionAuthorizationIntegrationTests.cs)
- [EF Core permission store](https://github.com/behrouzan/dotnet-auth/blob/main/src/Behrouzan.Auth.EntityFrameworkCore/Permissions/EfPermissionGrantStore.cs)
