using Behrouzan.Auth.DependencyInjection;
using Behrouzan.Auth.Permissions;
using Microsoft.Extensions.DependencyInjection;

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
}