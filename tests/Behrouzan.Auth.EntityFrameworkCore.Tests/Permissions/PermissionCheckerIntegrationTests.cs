using Behrouzan.Auth.DependencyInjection;
using Behrouzan.Auth.EntityFrameworkCore.DependencyInjection;
using Behrouzan.Auth.EntityFrameworkCore.Extensions;
using Behrouzan.Auth.EntityFrameworkCore.Permissions;
using Behrouzan.Auth.Permissions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Behrouzan.Auth.EntityFrameworkCore.Tests.Permissions;

public sealed class PermissionCheckerIntegrationTests
{
    [Fact]
    public async Task IsGrantedAsync_ShouldResolvePermissionThroughEntityFrameworkCore()
    {
        var services = CreateServices();

        using var serviceProvider =
            services.BuildServiceProvider(
                new ServiceProviderOptions
                {
                    ValidateScopes = true
                });

        using var scope =
            serviceProvider.CreateScope();

        var dbContext =
            scope.ServiceProvider
                .GetRequiredService<TestDbContext>();

        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();

        dbContext.UserRoles.Add(
            new IdentityUserRole<Guid>
            {
                UserId = userId,
                RoleId = roleId
            });

        dbContext.Set<RolePermissionGrant<Guid>>()
            .Add(
                new RolePermissionGrant<Guid>
                {
                    RoleId = roleId,
                    PermissionName = "Products.Create"
                });

        await dbContext.SaveChangesAsync();

        var checker =
            scope.ServiceProvider
                .GetRequiredService<
                    IPermissionChecker<Guid>>();

        var isGranted =
            await checker.IsGrantedAsync(
                userId,
                "Products.Create");

        Assert.True(isGranted);
    }

    [Fact]
    public async Task IsGrantedAsync_ShouldReturnFalse_WhenPermissionIsNotGranted()
    {
        var services = CreateServices();

        using var serviceProvider =
            services.BuildServiceProvider(
                new ServiceProviderOptions
                {
                    ValidateScopes = true
                });

        using var scope =
            serviceProvider.CreateScope();

        var dbContext =
            scope.ServiceProvider
                .GetRequiredService<TestDbContext>();

        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();

        dbContext.UserRoles.Add(
            new IdentityUserRole<Guid>
            {
                UserId = userId,
                RoleId = roleId
            });

        await dbContext.SaveChangesAsync();

        var checker =
            scope.ServiceProvider
                .GetRequiredService<IPermissionChecker<Guid>>();

        var isGranted =
            await checker.IsGrantedAsync(
                userId,
                "Products.Create");

        Assert.False(isGranted);
    }
    [Fact]
    public async Task IsGrantedAsync_ShouldReturnTrue_WhenAnyUserRoleHasPermission()
    {
        var services = CreateServices();

        using var serviceProvider =
            services.BuildServiceProvider(
                new ServiceProviderOptions
                {
                    ValidateScopes = true
                });

        using var scope =
            serviceProvider.CreateScope();

        var dbContext =
            scope.ServiceProvider
                .GetRequiredService<TestDbContext>();

        var userId = Guid.NewGuid();
        var firstRoleId = Guid.NewGuid();
        var secondRoleId = Guid.NewGuid();

        dbContext.UserRoles.AddRange(
            new IdentityUserRole<Guid>
            {
                UserId = userId,
                RoleId = firstRoleId
            },
            new IdentityUserRole<Guid>
            {
                UserId = userId,
                RoleId = secondRoleId
            });

        dbContext.Set<RolePermissionGrant<Guid>>()
            .Add(
                new RolePermissionGrant<Guid>
                {
                    RoleId = secondRoleId,
                    PermissionName = "Products.Create"
                });

        await dbContext.SaveChangesAsync();

        var checker =
            scope.ServiceProvider
                .GetRequiredService<IPermissionChecker<Guid>>();

        var isGranted =
            await checker.IsGrantedAsync(
                userId,
                "Products.Create");

        Assert.True(isGranted);
    }
    [Fact]
    public async Task IsGrantedAsync_ShouldReturnFalse_WhenPermissionIsNotDefined()
    {
        var services = CreateServices();

        using var serviceProvider =
            services.BuildServiceProvider(
                new ServiceProviderOptions
                {
                    ValidateScopes = true
                });

        using var scope =
            serviceProvider.CreateScope();

        var dbContext =
            scope.ServiceProvider
                .GetRequiredService<TestDbContext>();

        var userId = Guid.NewGuid();
        var roleId = Guid.NewGuid();

        dbContext.UserRoles.Add(
            new IdentityUserRole<Guid>
            {
                UserId = userId,
                RoleId = roleId
            });

        dbContext.Set<RolePermissionGrant<Guid>>()
            .Add(
                new RolePermissionGrant<Guid>
                {
                    RoleId = roleId,
                    PermissionName = "Products.OldPermission"
                });

        await dbContext.SaveChangesAsync();

        var checker =
            scope.ServiceProvider
                .GetRequiredService<IPermissionChecker<Guid>>();

        var isGranted =
            await checker.IsGrantedAsync(
                userId,
                "Products.OldPermission");

        Assert.False(isGranted);
    }

    private sealed class TestPermissionProvider
        : PermissionDefinitionProvider
    {
        public override void Define(
            IPermissionDefinitionContext context)
        {
            context
                .AddGroup(
                    "Products",
                    "Products")
                .AddPermission(
                    "Products.Create",
                    "Create products");
        }
    }

    private sealed class TestUser
        : IdentityUser<Guid>
    {
    }

    private sealed class TestRole
        : IdentityRole<Guid>
    {
    }

    private sealed class TestDbContext
        : IdentityDbContext<
            TestUser,
            TestRole,
            Guid>
    {
        public TestDbContext(
            DbContextOptions<TestDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(
            ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.ConfigureBehrouzanAuth<Guid>();
        }
    }

    private static ServiceCollection CreateServices()
    {
        var services =
            new ServiceCollection();

        services.AddDbContext<TestDbContext>(
            options =>
                options.UseInMemoryDatabase(
                    Guid.NewGuid().ToString()));

        services.AddBehrouzanAuth();

        services.AddPermissionDefinition<
            TestPermissionProvider>();

        services.AddBehrouzanAuthEntityFrameworkCore<
            TestDbContext,
            TestUser,
            TestRole,
            Guid>();

        return services;
    }
}