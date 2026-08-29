using Behrouzan.Auth.DependencyInjection;
using Behrouzan.Auth.Permissions;
using Microsoft.Extensions.DependencyInjection;

namespace Behrouzan.Auth.Tests.Permissions;

public class PermissionDefinitionValidationTests
{
    [Fact]
    public void Catalog_ShouldContainDefinedGroup()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        using var serviceProvider =
            services.BuildServiceProvider();

        var catalog =
            serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>();

        var group = Assert.Single(catalog.Groups);

        Assert.Equal("Products", group.Name);
    }

    [Fact]
    public void BuildingCatalog_ShouldThrow_WhenGroupAlreadyExists()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<DuplicateGroupProvider>();

        using var serviceProvider =
            services.BuildServiceProvider();

        Assert.Throws<InvalidOperationException>(
            () => serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>());
    }

    [Fact]
    public void BuildingCatalog_ShouldThrow_WhenPermissionExistsInAnotherGroup()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<
            DuplicatePermissionProvider>();

        using var serviceProvider =
            services.BuildServiceProvider();

        Assert.Throws<InvalidOperationException>(
            () => serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>());
    }

    private sealed class ProductPermissionProvider
        : PermissionDefinitionProvider
    {
        public override void Define(
            IPermissionDefinitionContext context)
        {
            context.AddGroup(
                "Products",
                "Products");
        }
    }

    private sealed class DuplicateGroupProvider
        : PermissionDefinitionProvider
    {
        public override void Define(
            IPermissionDefinitionContext context)
        {
            context.AddGroup("Products");
            context.AddGroup("Products");
        }
    }

    private sealed class DuplicatePermissionProvider
        : PermissionDefinitionProvider
    {
        public override void Define(
            IPermissionDefinitionContext context)
        {
            var products =
                context.AddGroup("Products");

            var administration =
                context.AddGroup("Administration");

            products.AddPermission(
                "Products.Create");

            administration.AddPermission(
                "Products.Create");
        }
    }
}