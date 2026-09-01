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
    }
}