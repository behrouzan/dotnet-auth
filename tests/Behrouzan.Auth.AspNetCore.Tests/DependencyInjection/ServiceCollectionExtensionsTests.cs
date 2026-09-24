using Behrouzan.Auth.AspNetCore.DependencyInjection;
using Behrouzan.Auth.AspNetCore.Users;
using Behrouzan.Auth.Permissions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Behrouzan.Auth.AspNetCore.Authorization;
using Behrouzan.Auth.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;


namespace Behrouzan.Auth.AspNetCore.Tests.DependencyInjection;

public sealed class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddBehrouzanTokenRefresh_ShouldRegisterScopedManagerOnly()
    {
        var services = new ServiceCollection();
        services.AddBehrouzanTokenRefresh<CustomTokenUser, CustomTokenKey>();

        var manager = services.Single(
            descriptor => descriptor.ServiceType ==
                typeof(TokenRefreshManager<CustomTokenUser, CustomTokenKey>));

        Assert.Equal(ServiceLifetime.Scoped, manager.Lifetime);
        Assert.DoesNotContain(
            services,
            descriptor => descriptor.ServiceType ==
                typeof(IRefreshTokenUserResolver<CustomTokenUser, CustomTokenKey>));
    }

    [Fact]
    public void AddBehrouzanTokenLogin_ShouldSupportCustomUserAndKeyResolver()
    {
        var services = new ServiceCollection();
        services.AddScoped<
            ITokenUserIdentityResolver<CustomTokenUser, CustomTokenKey>,
            CustomTokenUserIdentityResolver>();

        services.AddBehrouzanTokenLogin<CustomTokenUser, CustomTokenKey>();

        var manager = services.Single(
            descriptor => descriptor.ServiceType ==
                typeof(TokenLoginManager<CustomTokenUser, CustomTokenKey>));
        var resolver = services.Single(
            descriptor => descriptor.ServiceType ==
                typeof(ITokenUserIdentityResolver<CustomTokenUser, CustomTokenKey>));

        Assert.Equal(ServiceLifetime.Scoped, manager.Lifetime);
        Assert.Equal(typeof(CustomTokenUserIdentityResolver), resolver.ImplementationType);
        Assert.Equal(ServiceLifetime.Scoped, resolver.Lifetime);
    }

    [Fact]
    public void AddBehrouzanIdentityTokenLogin_ShouldRegisterStandardIdentityResolver()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanIdentityTokenLogin<TestUser, Guid>();

        var manager = services.Single(
            descriptor => descriptor.ServiceType ==
                typeof(TokenLoginManager<TestUser, Guid>));
        var resolver = services.Single(
            descriptor => descriptor.ServiceType ==
                typeof(ITokenUserIdentityResolver<TestUser, Guid>));

        Assert.Equal(ServiceLifetime.Scoped, manager.Lifetime);
        Assert.Equal(
            typeof(DefaultTokenUserIdentityResolver<TestUser, Guid>),
            resolver.ImplementationType);
        Assert.Equal(ServiceLifetime.Scoped, resolver.Lifetime);
    }

    [Fact]
    public void AddBehrouzanAccessTokens_ShouldRegisterIssuanceServices()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAccessTokens(options =>
        {
            options.Issuer = "https://issuer.example";
            options.Audience = "behrouzan-api";
        });

        var managerDescriptor = services.Single(
            descriptor => descriptor.ServiceType == typeof(AccessTokenManager));
        var timeProviderDescriptor = services.Single(
            descriptor => descriptor.ServiceType == typeof(TimeProvider));

        Assert.Equal(ServiceLifetime.Scoped, managerDescriptor.Lifetime);
        Assert.Equal(ServiceLifetime.Singleton, timeProviderDescriptor.Lifetime);
        Assert.DoesNotContain(
            services,
            descriptor => descriptor.ServiceType ==
                typeof(IAccessTokenSigningCredentialsProvider));
    }

    [Fact]
    public void AddBehrouzanAccessTokens_ShouldApplyConfiguration()
    {
        var services = new ServiceCollection();
        var lifetime = TimeSpan.FromMinutes(20);
        services.AddBehrouzanAccessTokens(options =>
        {
            options.Issuer = "https://issuer.example";
            options.Audience = "behrouzan-api";
            options.Lifetime = lifetime;
        });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<AccessTokenOptions>>().Value;

        Assert.Equal("https://issuer.example", options.Issuer);
        Assert.Equal("behrouzan-api", options.Audience);
        Assert.Equal(lifetime, options.Lifetime);
    }

    [Fact]
    public void AddBehrouzanAccessTokens_ShouldUseDefaultLifetime()
    {
        var services = new ServiceCollection();
        services.AddBehrouzanAccessTokens(options =>
        {
            options.Issuer = "https://issuer.example";
            options.Audience = "behrouzan-api";
        });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<AccessTokenOptions>>().Value;

        Assert.Equal(TimeSpan.FromMinutes(15), options.Lifetime);
    }

    [Theory]
    [InlineData("", "audience", 1)]
    [InlineData("   ", "audience", 1)]
    [InlineData("issuer", "", 1)]
    [InlineData("issuer", "   ", 1)]
    [InlineData("issuer", "audience", 0)]
    [InlineData("issuer", "audience", -1)]
    public void AddBehrouzanAccessTokens_ShouldRejectInvalidOptions(
        string issuer,
        string audience,
        int lifetimeTicks)
    {
        var services = new ServiceCollection();
        services.AddBehrouzanAccessTokens(options =>
        {
            options.Issuer = issuer;
            options.Audience = audience;
            options.Lifetime = TimeSpan.FromTicks(lifetimeTicks);
        });

        using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptions<AccessTokenOptions>>();

        Assert.Throws<OptionsValidationException>(() => _ = options.Value);
    }

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


    [Fact]
    public void AddBehrouzanPasswordSignIn_ShouldRegisterRequiredServices()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanPasswordSignIn<TestUser>();

        using var serviceProvider =
            services.BuildServiceProvider();

        var resolverDescriptor =
            services.Single(
                descriptor =>
                    descriptor.ServiceType ==
                    typeof(IUserSignInResolver<TestUser>));

        var managerDescriptor =
            services.Single(
                descriptor =>
                    descriptor.ServiceType ==
                    typeof(PasswordSignInManager<TestUser>));

        var authenticationManagerDescriptor =
            services.Single(
                descriptor =>
                    descriptor.ServiceType ==
                    typeof(PasswordAuthenticationManager<TestUser>));

        Assert.Equal(
            typeof(DefaultUserSignInResolver<TestUser>),
            resolverDescriptor.ImplementationType);

        Assert.Equal(
            ServiceLifetime.Scoped,
            resolverDescriptor.Lifetime);

        Assert.Equal(
            ServiceLifetime.Scoped,
            managerDescriptor.Lifetime);

        Assert.Equal(
            ServiceLifetime.Scoped,
            authenticationManagerDescriptor.Lifetime);
    }

    [Fact]
    public void AddBehrouzanPasswordSignIn_ShouldConfigureOptions()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanPasswordSignIn<TestUser>(
            options =>
            {
                options.AllowedIdentifiers =
                    SignInIdentifier.UserName |
                    SignInIdentifier.Email;

                options.LockoutOnFailure = false;
            });

        using var serviceProvider =
            services.BuildServiceProvider();

        var options =
            serviceProvider
                .GetRequiredService<
                    IOptions<PasswordSignInOptions>>()
                .Value;

        Assert.Equal(
            SignInIdentifier.UserName |
            SignInIdentifier.Email,
            options.AllowedIdentifiers);

        Assert.False(options.LockoutOnFailure);
    }

    [Fact]
    public void AddBehrouzanPasswordSignIn_ShouldUseDefaultOptions()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanPasswordSignIn<TestUser>();

        using var serviceProvider =
            services.BuildServiceProvider();

        var options =
            serviceProvider
                .GetRequiredService<
                    IOptions<PasswordSignInOptions>>()
                .Value;

        Assert.Equal(
            SignInIdentifier.UserName,
            options.AllowedIdentifiers);

        Assert.True(options.LockoutOnFailure);
    }


    [Fact]
    public void AddBehrouzanPasswordSignIn_ShouldPreserveExistingResolver()
    {
        var services =
            new ServiceCollection();

        services.AddScoped<
            IUserSignInResolver<TestUser>,
            CustomUserSignInResolver>();

        services.AddBehrouzanPasswordSignIn<TestUser>();

        using var serviceProvider =
            services.BuildServiceProvider();

        using var scope =
            serviceProvider.CreateScope();

        var resolver =
            scope.ServiceProvider
                .GetRequiredService<
                    IUserSignInResolver<TestUser>>();

        Assert.IsType<CustomUserSignInResolver>(
            resolver);
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

    private sealed class TestUser
        : IdentityUser<Guid>
    {
    }

    private sealed class CustomTokenUser
    {
    }

    private sealed class CustomTokenKey
    {
    }

    private sealed class CustomTokenUserIdentityResolver
        : ITokenUserIdentityResolver<CustomTokenUser, CustomTokenKey>
    {
        public Task<TokenUserIdentity<CustomTokenKey>> ResolveAsync(
            CustomTokenUser user,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                new TokenUserIdentity<CustomTokenKey>(
                    new CustomTokenKey(),
                    "custom-user-id"));
        }
    }

    private sealed class CustomUserSignInResolver
        : IUserSignInResolver<TestUser>
    {
        public Task<UserSignInResolution<TestUser>> ResolveAsync(
            string identifier,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                UserSignInResolution<TestUser>.NotFound());
        }
    }

}
