using Behrouzan.Auth.DependencyInjection;
using Behrouzan.Auth.Permissions;
using Microsoft.Extensions.DependencyInjection;

namespace Behrouzan.Auth.Tests.Permissions;

public sealed class RolePermissionManagerTests
{
    [Fact]
    public async Task GrantAsync_ShouldGrantPermission_WhenPermissionIsDefined()
    {
        var store = new FakeRolePermissionGrantStore();

        using var serviceProvider = CreateServiceProvider(store);

        var manager =
            serviceProvider.GetRequiredService<
                RolePermissionManager<Guid>>();

        var roleId = Guid.NewGuid();

        var result = await manager.GrantAsync(
            roleId,
            "Products.Create");

        Assert.True(result.IsSuccess);
        Assert.Null(result.ErrorCode);
        Assert.Contains(
            "Products.Create",
            store.GetPermissions(roleId));
    }

    [Fact]
    public async Task GrantAsync_ShouldReturnUnknownPermission_WhenPermissionIsNotDefined()
    {
        var store = new FakeRolePermissionGrantStore();

        using var serviceProvider = CreateServiceProvider(store);

        var manager =
            serviceProvider.GetRequiredService<
                RolePermissionManager<Guid>>();

        var result = await manager.GrantAsync(
            Guid.NewGuid(),
            "Products.Delete");

        Assert.False(result.IsSuccess);
        Assert.Equal(
            PermissionManagementErrorCode.UnknownPermission,
            result.ErrorCode);

        Assert.Equal(0, store.GrantCallCount);
    }

    [Fact]
    public async Task RevokeAsync_ShouldRevokePermission_WhenPermissionIsDefined()
    {
        var roleId = Guid.NewGuid();
        var store = new FakeRolePermissionGrantStore();

        await store.GrantAsync(
            roleId,
            "Products.Edit");

        using var serviceProvider = CreateServiceProvider(store);

        var manager =
            serviceProvider.GetRequiredService<
                RolePermissionManager<Guid>>();

        var result = await manager.RevokeAsync(
            roleId,
            "Products.Edit");

        Assert.True(result.IsSuccess);
        Assert.DoesNotContain(
            "Products.Edit",
            store.GetPermissions(roleId));
    }

    [Fact]
    public async Task RevokeAsync_ShouldReturnUnknownPermission_WhenPermissionIsNotDefined()
    {
        var store = new FakeRolePermissionGrantStore();

        using var serviceProvider = CreateServiceProvider(store);

        var manager =
            serviceProvider.GetRequiredService<
                RolePermissionManager<Guid>>();

        var result = await manager.RevokeAsync(
            Guid.NewGuid(),
            "Products.Delete");

        Assert.False(result.IsSuccess);
        Assert.Equal(
            PermissionManagementErrorCode.UnknownPermission,
            result.ErrorCode);

        Assert.Equal(0, store.RevokeCallCount);
    }

    [Fact]
    public async Task SetPermissionsAsync_ShouldReplacePermissions_WhenAllPermissionsAreDefined()
    {
        var roleId = Guid.NewGuid();
        var store = new FakeRolePermissionGrantStore();

        await store.GrantAsync(
            roleId,
            "Products.View");

        using var serviceProvider = CreateServiceProvider(store);

        var manager =
            serviceProvider.GetRequiredService<
                RolePermissionManager<Guid>>();

        var result = await manager.SetPermissionsAsync(
            roleId,
            ["Products.Create", "Products.Edit"]);

        Assert.True(result.IsSuccess);

        var permissions = store.GetPermissions(roleId);

        Assert.Equal(2, permissions.Count);
        Assert.Contains("Products.Create", permissions);
        Assert.Contains("Products.Edit", permissions);
        Assert.DoesNotContain("Products.View", permissions);
    }

    [Fact]
    public async Task SetPermissionsAsync_ShouldNotModifyStore_WhenAnyPermissionIsNotDefined()
    {
        var roleId = Guid.NewGuid();
        var store = new FakeRolePermissionGrantStore();

        await store.GrantAsync(
            roleId,
            "Products.View");

        using var serviceProvider = CreateServiceProvider(store);

        var manager =
            serviceProvider.GetRequiredService<
                RolePermissionManager<Guid>>();

        var result = await manager.SetPermissionsAsync(
            roleId,
            [
                "Products.Create",
                "Unknown.Permission",
                "Products.Edit"
            ]);

        Assert.False(result.IsSuccess);
        Assert.Equal(
            PermissionManagementErrorCode.UnknownPermission,
            result.ErrorCode);

        Assert.Equal(0, store.SetPermissionsCallCount);

        var permissions = store.GetPermissions(roleId);

        Assert.Single(permissions);
        Assert.Contains("Products.View", permissions);
    }

    [Fact]
    public async Task GetPermissionsAsync_ShouldReturnPermissionsFromStore()
    {
        var roleId = Guid.NewGuid();
        var store = new FakeRolePermissionGrantStore();

        await store.SetPermissionsAsync(
            roleId,
            ["Products.View", "Products.Edit"]);

        using var serviceProvider = CreateServiceProvider(store);

        var manager =
            serviceProvider.GetRequiredService<
                RolePermissionManager<Guid>>();

        var permissions =
            await manager.GetPermissionsAsync(roleId);

        Assert.Equal(2, permissions.Count);
        Assert.Contains("Products.View", permissions);
        Assert.Contains("Products.Edit", permissions);
    }

    private static ServiceProvider CreateServiceProvider(
        FakeRolePermissionGrantStore store)
    {
        var services = new ServiceCollection();

        services.AddBehrouzanAuth();
        services.AddPermissionDefinition<
            ProductPermissionProvider>();

        services.AddSingleton<
            IRolePermissionGrantStore<Guid>>(store);

        return services.BuildServiceProvider();
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

    private sealed class FakeRolePermissionGrantStore
        : IRolePermissionGrantStore<Guid>
    {
        private readonly Dictionary<Guid, HashSet<string>>
            _permissions = [];

        public int GrantCallCount { get; private set; }

        public int RevokeCallCount { get; private set; }

        public int SetPermissionsCallCount { get; private set; }

        public Task GrantAsync(
            Guid roleId,
            string permissionName,
            CancellationToken cancellationToken = default)
        {
            GrantCallCount++;

            GetOrCreate(roleId).Add(permissionName);

            return Task.CompletedTask;
        }

        public Task RevokeAsync(
            Guid roleId,
            string permissionName,
            CancellationToken cancellationToken = default)
        {
            RevokeCallCount++;

            if (_permissions.TryGetValue(
                roleId,
                out var permissions))
            {
                permissions.Remove(permissionName);
            }

            return Task.CompletedTask;
        }

        public Task<IReadOnlyCollection<string>>
            GetPermissionsAsync(
                Guid roleId,
                CancellationToken cancellationToken = default)
        {
            IReadOnlyCollection<string> result =
                GetPermissions(roleId);

            return Task.FromResult(result);
        }

        public Task SetPermissionsAsync(
            Guid roleId,
            IReadOnlyCollection<string> permissionNames,
            CancellationToken cancellationToken = default)
        {
            SetPermissionsCallCount++;

            _permissions[roleId] =
                new HashSet<string>(
                    permissionNames,
                    StringComparer.Ordinal);

            return Task.CompletedTask;
        }

        public IReadOnlyCollection<string> GetPermissions(
            Guid roleId)
        {
            if (!_permissions.TryGetValue(
                roleId,
                out var permissions))
            {
                return [];
            }

            return permissions.ToArray();
        }

        private HashSet<string> GetOrCreate(Guid roleId)
        {
            if (!_permissions.TryGetValue(
                roleId,
                out var permissions))
            {
                permissions =
                    new HashSet<string>(
                        StringComparer.Ordinal);

                _permissions.Add(
                    roleId,
                    permissions);
            }

            return permissions;
        }
    }
}