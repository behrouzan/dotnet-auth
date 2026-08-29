using Behrouzan.Auth.DependencyInjection;
using Behrouzan.Auth.Permissions;
using Microsoft.Extensions.DependencyInjection;

namespace Behrouzan.Auth.Tests.Permissions;

public class PermissionDefinitionProviderTests
{
    [Fact]
    public void Define_ShouldAllowProviderToDefinePermissions()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<TestPermissionDefinitionProvider>();

        using var serviceProvider =
            services.BuildServiceProvider();

        var catalog =
            serviceProvider.GetRequiredService<
                PermissionDefinitionCatalog>();

        var group = Assert.Single(catalog.Groups);
        var permission = Assert.Single(group.Permissions);

        Assert.Equal("Products", group.Name);
        Assert.Equal("Products.Create", permission.Name);
    }

    private sealed class TestPermissionDefinitionProvider
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
                "Products.Create",
                "Create products");
        }
    }
}