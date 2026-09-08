using Behrouzan.Auth.DependencyInjection;
using Behrouzan.Auth.Permissions;
using Microsoft.Extensions.DependencyInjection;
using Behrouzan.Auth.Authentication;
using Microsoft.Extensions.Options;


namespace Behrouzan.Auth.Tests.DependencyInjection;

public class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddBehrouzanAuth_ShouldRegisterCatalogAsSingleton()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanAuth();

        using var serviceProvider =
            services.BuildServiceProvider();

        var first =
            serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>();

        var second =
            serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>();

        Assert.Same(first, second);
    }

    [Fact]
    public void AddPermissionDefinition_ShouldIncludeProviderDefinitionsInCatalog()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanAuth();

        services.AddPermissionDefinition<
            TestPermissionProvider>();

        using var serviceProvider =
            services.BuildServiceProvider();

        var catalog =
            serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>();

        var group =
            Assert.Single(catalog.Groups);

        Assert.Equal("Products", group.Name);

        var permission =
            Assert.Single(group.Permissions);

        Assert.Equal(
            "Products.View",
            permission.Name);
    }

    [Fact]
    public void AddBehrouzanAuth_ShouldNotDuplicateCoreServices()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddBehrouzanAuth();

        using var serviceProvider =
            services.BuildServiceProvider();

        var catalogs =
            serviceProvider
                .GetServices<PermissionDefinitionCatalog>()
                .ToArray();

        Assert.Single(catalogs);
    }

    [Fact]
    public void AddPermissionDefinition_ShouldNotRegisterSameProviderTwice()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();

        services.AddPermissionDefinition<TestPermissionProvider>();
        services.AddPermissionDefinition<TestPermissionProvider>();

        using var serviceProvider =
            services.BuildServiceProvider();

        var catalog =
            serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>();

        Assert.Single(catalog.Groups);
    }


    private sealed class TestPermissionProvider
        : PermissionDefinitionProvider
    {
        public override void Define(
            IPermissionDefinitionContext context)
        {
            var products =
                context.AddGroup(
                    "Products",
                    "Products");

            products.AddPermission(
                "Products.View",
                "View products");
        }
    }

    [Fact]
    public void AddRefreshTokens_UsesDefaultOptions_WhenNoConfigurationIsProvided()
    {
        var services = new ServiceCollection();

        services.AddRefreshTokens();

        using var serviceProvider = services.BuildServiceProvider();

        var options = serviceProvider
            .GetRequiredService<IOptions<RefreshTokenOptions>>()
            .Value;

        Assert.Equal(TimeSpan.FromDays(30), options.Lifetime);
    }

    [Fact]
    public void AddRefreshTokens_AppliesCustomConfiguration()
    {
        var services = new ServiceCollection();

        services.AddRefreshTokens(options =>
        {
            options.Lifetime = TimeSpan.FromDays(14);
        });

        using var serviceProvider = services.BuildServiceProvider();

        var options = serviceProvider
            .GetRequiredService<IOptions<RefreshTokenOptions>>()
            .Value;

        Assert.Equal(TimeSpan.FromDays(14), options.Lifetime);
    }

    [Fact]
    public void AddRefreshTokens_RejectsNonPositiveLifetime()
    {
        var services = new ServiceCollection();

        services.AddRefreshTokens(options =>
        {
            options.Lifetime = TimeSpan.Zero;
        });

        using var serviceProvider = services.BuildServiceProvider();

        var options = serviceProvider
            .GetRequiredService<IOptions<RefreshTokenOptions>>();

        Assert.Throws<OptionsValidationException>(
            () => _ = options.Value);
    }
}