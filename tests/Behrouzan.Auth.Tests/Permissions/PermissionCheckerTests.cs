using Behrouzan.Auth.DependencyInjection;
using Behrouzan.Auth.Permissions;
using Microsoft.Extensions.DependencyInjection;

namespace Behrouzan.Auth.Tests.Permissions;

public sealed class PermissionCheckerTests
{
    [Fact]
    public async Task IsGrantedAsync_ShouldReturnTrue_WhenPermissionIsGranted()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        services.AddSingleton<IPermissionGrantStore<Guid>>(
            new FakePermissionGrantStore(
                ["Products.View", "Products.Create"]));


        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        var result =
            await checker.IsGrantedAsync(
                Guid.NewGuid(),
                "Products.Create");

        Assert.True(result);
    }

    private sealed class FakePermissionGrantStore
        : IPermissionGrantStore<Guid>
    {
        public int CallCount { get; private set; }

        private readonly IReadOnlyCollection<string>
            _permissions;

        public FakePermissionGrantStore(
            IReadOnlyCollection<string> permissions)
        {
            _permissions = permissions;
        }

        public Task<IReadOnlyCollection<string>>
            GetGrantedPermissionsAsync(
                Guid userId,
                CancellationToken cancellationToken = default)
        {
            CallCount++;
            return Task.FromResult(_permissions);
        }
    }

    private sealed class ProductPermissionProvider
        : PermissionDefinitionProvider
    {
        public override void Define(
            IPermissionDefinitionContext context)
        {
            var products =
                context.AddGroup("Products");

            products.AddPermission("Products.View");
            products.AddPermission("Products.Create");
        }
    }

    [Fact]
    public async Task IsGrantedAsync_ShouldReturnFalse_WhenPermissionIsNotGranted()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        services.AddSingleton<IPermissionGrantStore<Guid>>(
            new FakePermissionGrantStore(
                ["Products.View"]));

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        var result =
            await checker.IsGrantedAsync(
                Guid.NewGuid(),
                "Products.Create");

        Assert.False(result);
    }

    [Fact]
    public async Task IsGrantedAsync_ShouldNotQueryStore_WhenPermissionIsNotDefined()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        var store =
            new FakePermissionGrantStore(
                ["Products.View", "Products.Create"]);

        services.AddSingleton<IPermissionGrantStore<Guid>>(store);

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        var result =
            await checker.IsGrantedAsync(
                Guid.NewGuid(),
                "Products.Delete");

        Assert.False(result);
        Assert.Equal(0, store.CallCount);
    }
}