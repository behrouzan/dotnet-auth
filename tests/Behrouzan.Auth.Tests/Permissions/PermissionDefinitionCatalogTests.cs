using Behrouzan.Auth.DependencyInjection;
using Behrouzan.Auth.Permissions;
using Microsoft.Extensions.DependencyInjection;

namespace Behrouzan.Auth.Tests.Permissions;

public class PermissionDefinitionCatalogTests
{
    [Fact]
    public void Catalog_ShouldContainDefinitionsFromAllProviders()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();
        services.AddPermissionDefinition<OrderPermissionProvider>();

        using var serviceProvider =
            services.BuildServiceProvider();

        var catalog =
            serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>();

        Assert.Equal(2, catalog.Groups.Count);

        Assert.Contains(
            catalog.Groups,
            group => group.Name == "Products");

        Assert.Contains(
            catalog.Groups,
            group => group.Name == "Orders");
    }

    private sealed class ProductPermissionProvider
        : PermissionDefinitionProvider
    {
        public override void Define(
            IPermissionDefinitionContext context)
        {
            var products =
                context.AddGroup("Products");

            products.AddPermission(
                "Products.View");
        }
    }

    [Fact]
    public void Catalog_ShouldPreventPermissionChangesAfterBuild()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        using var serviceProvider =
            services.BuildServiceProvider();

        var catalog =
            serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>();

        var products = Assert.Single(catalog.Groups);

        Assert.Throws<InvalidOperationException>(
            () => products.AddPermission(
                "Products.Delete"));
    }

    private sealed class OrderPermissionProvider
        : PermissionDefinitionProvider
    {
        public override void Define(
            IPermissionDefinitionContext context)
        {
            var orders =
                context.AddGroup("Orders");

            orders.AddPermission(
                "Orders.View");
        }
    }

    [Fact]
    public void TryGetPermission_ShouldReturnPermission_WhenPermissionExists()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        using var serviceProvider =
            services.BuildServiceProvider();

        var catalog =
            serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>();

        var found =
            catalog.TryGetPermission(
                "Products.View",
                out var permission);

        Assert.True(found);
        Assert.NotNull(permission);
        Assert.Equal(
            "Products.View",
            permission.Name);
    }

    [Fact]
    public void TryGetPermission_ShouldReturnFalse_WhenPermissionDoesNotExist()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        using var serviceProvider =
            services.BuildServiceProvider();

        var catalog =
            serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>();

        var found =
            catalog.TryGetPermission(
                "Products.Delete",
                out var permission);

        Assert.False(found);
        Assert.Null(permission);
    }
}