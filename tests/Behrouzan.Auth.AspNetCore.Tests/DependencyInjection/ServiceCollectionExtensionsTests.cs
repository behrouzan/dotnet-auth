using Behrouzan.Auth.AspNetCore.DependencyInjection;
using Behrouzan.Auth.AspNetCore.Users;
using Behrouzan.Auth.Permissions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Behrouzan.Auth.AspNetCore.Authorization;

namespace Behrouzan.Auth.AspNetCore.Tests.DependencyInjection;

public sealed class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddBehrouzanAuthAspNetCore_ShouldRegisterRequiredServices()
    {
        var services =
            new ServiceCollection();

        services.AddAuthorization();

        services.AddSingleton<
            IPermissionChecker<Guid>,
            FakePermissionChecker>();

        services.AddBehrouzanAuthAspNetCore<Guid>();

        using var serviceProvider =
            services.BuildServiceProvider(
                new ServiceProviderOptions
                {
                    ValidateScopes = true
                });

        using var scope =
            serviceProvider.CreateScope();

        var resolver =
            scope.ServiceProvider
                .GetRequiredService<
                    IUserIdResolver<Guid>>();

        var handlers =
            scope.ServiceProvider
                .GetServices<IAuthorizationHandler>()
                .ToArray();

        var policyProvider =
            scope.ServiceProvider
                .GetRequiredService<
                    IAuthorizationPolicyProvider>();

        Assert.IsType<
            DefaultUserIdResolver<Guid>>(
                resolver);

        Assert.Contains(
            handlers,
            handler =>
                handler is
                    PermissionAuthorizationHandler<Guid>);

        Assert.IsType<PermissionAuthorizationPolicyProvider>(policyProvider);
    }

    [Fact]
    public void AddBehrouzanAuthAspNetCore_ShouldPreserveExistingUserIdResolver()
    {
        var services =
            new ServiceCollection();

        services.AddScoped<
            IUserIdResolver<Guid>,
            CustomUserIdResolver>();

        services.AddBehrouzanAuthAspNetCore<Guid>();

        using var serviceProvider =
            services.BuildServiceProvider();

        using var scope =
            serviceProvider.CreateScope();

        var resolver =
            scope.ServiceProvider
                .GetRequiredService<
                    IUserIdResolver<Guid>>();

        Assert.IsType<CustomUserIdResolver>(
            resolver);
    }

    [Fact]
    public async Task AddBehrouzanAuthAspNetCore_ShouldRegisterDynamicPermissionPolicyProvider()
    {
        var services =
            new ServiceCollection();

        services.AddAuthorization();

        services.AddBehrouzanAuthAspNetCore<Guid>();

        using var serviceProvider =
            services.BuildServiceProvider();

        var policyProvider =
            serviceProvider
                .GetRequiredService<
                    IAuthorizationPolicyProvider>();

        var policy =
            await policyProvider.GetPolicyAsync(
                "Permission:Products.Create");

        Assert.NotNull(policy);

        var requirement =
            Assert.Single(
                policy.Requirements
                    .OfType<PermissionRequirement>());

        Assert.Equal(
            "Products.Create",
            requirement.PermissionName);
    }

    private sealed class FakePermissionChecker
        : IPermissionChecker<Guid>
    {
        public Task<bool> IsGrantedAsync(
            Guid userId,
            string permissionName,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(false);
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

    private sealed class CustomUserIdResolver
    : IUserIdResolver<Guid>
    {
        public bool TryResolve(
            System.Security.Claims.ClaimsPrincipal principal,
            out Guid userId)
        {
            userId = Guid.Empty;
            return false;
        }
    }
}