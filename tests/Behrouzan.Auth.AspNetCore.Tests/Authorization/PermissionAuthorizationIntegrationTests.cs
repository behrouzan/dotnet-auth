using System.Security.Claims;
using Behrouzan.Auth.AspNetCore.Authorization;
using Behrouzan.Auth.AspNetCore.DependencyInjection;
using Behrouzan.Auth.Permissions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;


namespace Behrouzan.Auth.AspNetCore.Tests.Authorization;

public sealed class PermissionAuthorizationIntegrationTests
{
    [Fact]
    public async Task AuthorizeAsync_ShouldSucceed_WhenPermissionIsGranted()
    {
        var userId = Guid.NewGuid();

        var services =
            new ServiceCollection();

        services.AddAuthorization();

        services.AddLogging();
        services.AddAuthorization();

        services.AddSingleton<
            IPermissionChecker<Guid>>(
                new FakePermissionChecker(
                    userId,
                    "Products.Create",
                    true));

        services.AddBehrouzanAuthAspNetCore<Guid>();


        using var serviceProvider =
            services.BuildServiceProvider(
                new ServiceProviderOptions
                {
                    ValidateScopes = true
                });

        using var scope =
            serviceProvider.CreateScope();

        var authorizationService =
            scope.ServiceProvider
                .GetRequiredService<
                    IAuthorizationService>();

        var user =
            CreatePrincipal(
                userId.ToString());

        var result =
            await authorizationService.AuthorizeAsync(
                user,
                resource: null,
                "Permission:Products.Create");

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task AuthorizeAsync_ShouldFail_WhenPermissionIsNotGranted()
    {
        var userId = Guid.NewGuid();

        var services =
            new ServiceCollection();

        services.AddAuthorization();

        services.AddLogging();
        services.AddAuthorization();

        services.AddSingleton<
            IPermissionChecker<Guid>>(
                new FakePermissionChecker(
                    userId,
                    "Products.Create",
                    false));

        services.AddBehrouzanAuthAspNetCore<Guid>();

        using var serviceProvider =
            services.BuildServiceProvider(
                new ServiceProviderOptions
                {
                    ValidateScopes = true
                });

        using var scope =
            serviceProvider.CreateScope();

        var authorizationService =
            scope.ServiceProvider
                .GetRequiredService<
                    IAuthorizationService>();

        var user =
            CreatePrincipal(
                userId.ToString());

        var result =
            await authorizationService.AuthorizeAsync(
                user,
                resource: null,
                "Permission:Products.Create");

        Assert.False(result.Succeeded);
    }

    [Fact]
    public async Task AuthorizeAsync_ShouldSucceed_WhenAnyPermissionIsGranted()
    {
        var userId = Guid.NewGuid();

        var services =
            new ServiceCollection();

        services.AddLogging();
        services.AddAuthorization();

        services.AddSingleton<
            IPermissionChecker<Guid>>(
                new SetPermissionChecker(
                    ["Products.Edit"]));

        services.AddBehrouzanAuthAspNetCore<Guid>();

        using var serviceProvider =
            services.BuildServiceProvider();

        using var scope =
            serviceProvider.CreateScope();

        var authorizationService =
            scope.ServiceProvider
                .GetRequiredService<IAuthorizationService>();

        var user =
            CreatePrincipal(userId.ToString());

        var result =
            await authorizationService.AuthorizeAsync(
                user,
                resource: null,
                "PermissionAny:Products.Create|Products.Edit");

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task AuthorizeAsync_ShouldFail_WhenNotAllPermissionsAreGranted()
    {
        var userId = Guid.NewGuid();

        var services =
            new ServiceCollection();

        services.AddLogging();
        services.AddAuthorization();

        services.AddSingleton<
            IPermissionChecker<Guid>>(
                new SetPermissionChecker(
                    ["Products.Edit"]));

        services.AddBehrouzanAuthAspNetCore<Guid>();

        using var serviceProvider =
            services.BuildServiceProvider();

        using var scope =
            serviceProvider.CreateScope();

        var authorizationService =
            scope.ServiceProvider
                .GetRequiredService<IAuthorizationService>();

        var user =
            CreatePrincipal(userId.ToString());

        var result =
            await authorizationService.AuthorizeAsync(
                user,
                resource: null,
                "PermissionAll:Products.Edit|Products.View");

        Assert.False(result.Succeeded);
    }

    private static ClaimsPrincipal CreatePrincipal(
        string userId)
    {
        var identity =
            new ClaimsIdentity(
                [
                    new Claim(
                        ClaimTypes.NameIdentifier,
                        userId)
                ],
                authenticationType: "Test");

        return new ClaimsPrincipal(identity);
    }

    private sealed class FakePermissionChecker
        : IPermissionChecker<Guid>
    {
        private readonly Guid _expectedUserId;
        private readonly string _expectedPermissionName;
        private readonly bool _result;

        public FakePermissionChecker(
            Guid expectedUserId,
            string expectedPermissionName,
            bool result)
        {
            _expectedUserId = expectedUserId;
            _expectedPermissionName =
                expectedPermissionName;
            _result = result;
        }

        public Task<bool> IsGrantedAsync(
            Guid userId,
            string permissionName,
            CancellationToken cancellationToken = default)
        {
            Assert.Equal(
                _expectedUserId,
                userId);

            Assert.Equal(
                _expectedPermissionName,
                permissionName);

            return Task.FromResult(_result);
        }

        public Task<bool> IsAnyGrantedAsync(
    Guid userId,
    IEnumerable<string> permissionNames,
    CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }

        public Task<bool> AreAllGrantedAsync(
            Guid userId,
            IEnumerable<string> permissionNames,
            CancellationToken cancellationToken = default)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class SetPermissionChecker
    : IPermissionChecker<Guid>
    {
        private readonly HashSet<string> _grantedPermissions;

        public SetPermissionChecker(
            IEnumerable<string> grantedPermissions)
        {
            _grantedPermissions =
                grantedPermissions.ToHashSet(
                    StringComparer.Ordinal);
        }

        public Task<bool> IsGrantedAsync(
            Guid userId,
            string permissionName,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _grantedPermissions.Contains(permissionName));
        }

        public Task<bool> IsAnyGrantedAsync(
            Guid userId,
            IEnumerable<string> permissionNames,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                permissionNames.Any(
                    _grantedPermissions.Contains));
        }

        public Task<bool> AreAllGrantedAsync(
            Guid userId,
            IEnumerable<string> permissionNames,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                permissionNames.All(
                    _grantedPermissions.Contains));
        }
    }

    [Fact]
    public async Task AuthorizeAsync_ShouldFail_WhenNoAnyPermissionIsGranted()
    {
        var userId = Guid.NewGuid();

        var services =
            new ServiceCollection();

        services.AddLogging();
        services.AddAuthorization();

        services.AddSingleton<
            IPermissionChecker<Guid>>(
                new SetPermissionChecker(
                    ["Orders.View"]));

        services.AddBehrouzanAuthAspNetCore<Guid>();

        using var serviceProvider =
            services.BuildServiceProvider();

        using var scope =
            serviceProvider.CreateScope();

        var authorizationService =
            scope.ServiceProvider
                .GetRequiredService<IAuthorizationService>();

        var user =
            CreatePrincipal(userId.ToString());

        var result =
            await authorizationService.AuthorizeAsync(
                user,
                resource: null,
                "PermissionAny:Products.Create|Products.Edit");

        Assert.False(result.Succeeded);
    }
    [Fact]
    public async Task AuthorizeAsync_ShouldSucceed_WhenAllPermissionsAreGranted()
    {
        var userId = Guid.NewGuid();

        var services =
            new ServiceCollection();

        services.AddLogging();
        services.AddAuthorization();

        services.AddSingleton<
            IPermissionChecker<Guid>>(
                new SetPermissionChecker(
                [
                    "Products.Edit",
                "Products.View"
                ]));

        services.AddBehrouzanAuthAspNetCore<Guid>();

        using var serviceProvider =
            services.BuildServiceProvider();

        using var scope =
            serviceProvider.CreateScope();

        var authorizationService =
            scope.ServiceProvider
                .GetRequiredService<IAuthorizationService>();

        var user =
            CreatePrincipal(userId.ToString());

        var result =
            await authorizationService.AuthorizeAsync(
                user,
                resource: null,
                "PermissionAll:Products.Edit|Products.View");

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task AuthorizeAsync_ShouldSupportRegularAspNetCorePolicy()
    {
        var services =
            new ServiceCollection();

        services.AddLogging();

        services.AddAuthorization(options =>
        {
            options.AddPolicy(
                "CustomPolicy",
                policy =>
                    policy.RequireClaim(
                        "custom",
                        "yes"));
        });
        services.AddSingleton<
            IPermissionChecker<Guid>>(
                new SetPermissionChecker([]));

        services.AddBehrouzanAuthAspNetCore<Guid>();

        using var serviceProvider =
            services.BuildServiceProvider();

        using var scope =
            serviceProvider.CreateScope();

        var authorizationService =
            scope.ServiceProvider
                .GetRequiredService<IAuthorizationService>();

        var user =
            new ClaimsPrincipal(
                new ClaimsIdentity(
                [
                    new Claim(
                    ClaimTypes.NameIdentifier,
                    Guid.NewGuid().ToString()),

                new Claim(
                    "custom",
                    "yes")
                ],
                authenticationType: "Test"));

        var result =
            await authorizationService.AuthorizeAsync(
                user,
                resource: null,
                "CustomPolicy");

        Assert.True(result.Succeeded);
    }
}