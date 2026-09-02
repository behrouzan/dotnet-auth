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
            products.AddPermission("Products.Edit");
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

    [Fact]
    public async Task IsAnyGrantedAsync_ShouldReturnTrue_WhenOnePermissionIsGranted()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        var store =
            new FakePermissionGrantStore(
                ["Products.Edit"]);

        services.AddSingleton<
            IPermissionGrantStore<Guid>>(store);

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        var result =
            await checker.IsAnyGrantedAsync(
                Guid.NewGuid(),
                ["Products.View", "Products.Edit"]);

        Assert.True(result);
        Assert.Equal(1, store.CallCount);
    }

    [Fact]
    public async Task IsAnyGrantedAsync_ShouldReturnFalse_WhenNoneAreGranted()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        var store =
            new FakePermissionGrantStore(
                ["Products.Create"]);

        services.AddSingleton<
            IPermissionGrantStore<Guid>>(store);

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        var result =
            await checker.IsAnyGrantedAsync(
                Guid.NewGuid(),
                ["Products.View", "Products.Edit"]);

        Assert.False(result);
        Assert.Equal(1, store.CallCount);
    }


    [Fact]
    public async Task IsAnyGrantedAsync_ShouldReturnTrue_WhenDefinedGrantedPermissionExistsAlongsideUndefinedPermission()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        var store =
            new FakePermissionGrantStore(
                ["Products.Edit"]);

        services.AddSingleton<
            IPermissionGrantStore<Guid>>(store);

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        var result =
            await checker.IsAnyGrantedAsync(
                Guid.NewGuid(),
                ["Unknown.Permission", "Products.Edit"]);

        Assert.True(result);
        Assert.Equal(1, store.CallCount);
    }


    [Fact]
    public async Task IsAnyGrantedAsync_ShouldNotQueryStore_WhenAllPermissionsAreUndefined()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        var store =
            new FakePermissionGrantStore(
                ["Products.View"]);

        services.AddSingleton<
            IPermissionGrantStore<Guid>>(store);

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        var result =
            await checker.IsAnyGrantedAsync(
                Guid.NewGuid(),
                ["Unknown.One", "Unknown.Two"]);

        Assert.False(result);
        Assert.Equal(0, store.CallCount);
    }

    [Fact]
    public async Task AreAllGrantedAsync_ShouldReturnTrue_WhenAllPermissionsAreGranted()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        var store =
            new FakePermissionGrantStore(
                ["Products.View", "Products.Edit"]);

        services.AddSingleton<
            IPermissionGrantStore<Guid>>(store);

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        var result =
            await checker.AreAllGrantedAsync(
                Guid.NewGuid(),
                ["Products.View", "Products.Edit"]);

        Assert.True(result);
        Assert.Equal(1, store.CallCount);
    }

    [Fact]
    public async Task AreAllGrantedAsync_ShouldReturnFalse_WhenOnePermissionIsNotGranted()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        var store =
            new FakePermissionGrantStore(
                ["Products.View"]);

        services.AddSingleton<
            IPermissionGrantStore<Guid>>(store);

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        var result =
            await checker.AreAllGrantedAsync(
                Guid.NewGuid(),
                ["Products.View", "Products.Edit"]);

        Assert.False(result);
        Assert.Equal(1, store.CallCount);
    }
    [Fact]
    public async Task AreAllGrantedAsync_ShouldNotQueryStore_WhenPermissionIsUndefined()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        var store =
            new FakePermissionGrantStore(
                ["Products.View", "Products.Edit"]);

        services.AddSingleton<
            IPermissionGrantStore<Guid>>(store);

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        var result =
            await checker.AreAllGrantedAsync(
                Guid.NewGuid(),
                ["Products.View", "Unknown.Permission"]);

        Assert.False(result);
        Assert.Equal(0, store.CallCount);
    }

    [Fact]
    public async Task IsAnyGrantedAsync_ShouldThrow_WhenPermissionNamesIsEmpty()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        services.AddSingleton<IPermissionGrantStore<Guid>>(
            new FakePermissionGrantStore([]));

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        await Assert.ThrowsAsync<ArgumentException>(
            () => checker.IsAnyGrantedAsync(
                Guid.NewGuid(),
                []));
    }
    [Fact]
    public async Task AreAllGrantedAsync_ShouldThrow_WhenPermissionNamesIsEmpty()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        services.AddSingleton<IPermissionGrantStore<Guid>>(
            new FakePermissionGrantStore([]));

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        await Assert.ThrowsAsync<ArgumentException>(
            () => checker.AreAllGrantedAsync(
                Guid.NewGuid(),
                []));
    }

    [Fact]
    public async Task IsAnyGrantedAsync_ShouldThrow_WhenPermissionNameIsWhitespace()
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        services.AddSingleton<IPermissionGrantStore<Guid>>(
            new FakePermissionGrantStore([]));

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        await Assert.ThrowsAsync<ArgumentException>(
            () => checker.IsAnyGrantedAsync(
                Guid.NewGuid(),
                ["Products.View", "   "]));
    }

    [Fact]
    public async Task AreAllGrantedAsync_ShouldHandleDuplicatePermissions()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        var store =
            new FakePermissionGrantStore(
                ["Products.View"]);

        services.AddSingleton<
            IPermissionGrantStore<Guid>>(store);

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        var result =
            await checker.AreAllGrantedAsync(
                Guid.NewGuid(),
                [
                    "Products.View",
                "Products.View"
                ]);

        Assert.True(result);
        Assert.Equal(1, store.CallCount);
    }

    [Fact]
    public async Task IsAnyGrantedAsync_ShouldThrow_WhenPermissionNamesIsNull()
    {
        var services =
            new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<ProductPermissionProvider>();

        services.AddSingleton<
            IPermissionGrantStore<Guid>>(
                new FakePermissionGrantStore([]));

        using var serviceProvider =
            services.BuildServiceProvider();

        var checker =
            serviceProvider.GetRequiredService<
                IPermissionChecker<Guid>>();

        await Assert.ThrowsAsync<ArgumentNullException>(
            () => checker.IsAnyGrantedAsync(
                Guid.NewGuid(),
                null!));
    }
}