using Behrouzan.Auth.EntityFrameworkCore.Extensions;
using Behrouzan.Auth.EntityFrameworkCore.Permissions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Behrouzan.Auth.EntityFrameworkCore.Tests.Permissions;

public sealed class RolePermissionGrantStoreTests
{
    [Fact]
    public async Task GrantAsync_ShouldPersistPermission()
    {
        await using var fixture = await CreateFixtureAsync();

        var roleId = await AddRoleAsync(fixture.Context);
        var store = CreateStore(fixture.Context);

        await store.GrantAsync(
            roleId,
            "Products.View");

        var permissions =
            await store.GetPermissionsAsync(roleId);

        Assert.Single(permissions);
        Assert.Contains("Products.View", permissions);
    }

    [Fact]
    public async Task GrantAsync_ShouldBeIdempotent_WhenPermissionIsAlreadyGranted()
    {
        await using var fixture = await CreateFixtureAsync();

        var roleId = await AddRoleAsync(fixture.Context);
        var store = CreateStore(fixture.Context);

        await store.GrantAsync(
            roleId,
            "Products.View");

        await store.GrantAsync(
            roleId,
            "Products.View");

        var permissions =
            await store.GetPermissionsAsync(roleId);

        Assert.Single(permissions);
        Assert.Contains("Products.View", permissions);
    }

    [Fact]
    public async Task RevokeAsync_ShouldRemoveExistingPermission()
    {
        await using var fixture = await CreateFixtureAsync();

        var roleId = await AddRoleAsync(fixture.Context);
        var store = CreateStore(fixture.Context);

        await store.GrantAsync(
            roleId,
            "Products.View");

        await store.RevokeAsync(
            roleId,
            "Products.View");

        var permissions =
            await store.GetPermissionsAsync(roleId);

        Assert.Empty(permissions);
    }

    [Fact]
    public async Task RevokeAsync_ShouldBeIdempotent_WhenPermissionIsNotGranted()
    {
        await using var fixture = await CreateFixtureAsync();

        var roleId = await AddRoleAsync(fixture.Context);
        var store = CreateStore(fixture.Context);

        await store.RevokeAsync(
            roleId,
            "Products.View");

        var permissions =
            await store.GetPermissionsAsync(roleId);

        Assert.Empty(permissions);
    }

    [Fact]
    public async Task GetPermissionsAsync_ShouldReturnOnlyPermissionsForSpecifiedRole()
    {
        await using var fixture = await CreateFixtureAsync();

        var firstRoleId =
            await AddRoleAsync(fixture.Context);

        var secondRoleId =
            await AddRoleAsync(fixture.Context);

        var store = CreateStore(fixture.Context);

        await store.GrantAsync(
            firstRoleId,
            "Products.View");

        await store.GrantAsync(
            firstRoleId,
            "Products.Edit");

        await store.GrantAsync(
            secondRoleId,
            "Orders.View");

        var permissions =
            await store.GetPermissionsAsync(firstRoleId);

        Assert.Equal(2, permissions.Count);
        Assert.Contains("Products.View", permissions);
        Assert.Contains("Products.Edit", permissions);
        Assert.DoesNotContain("Orders.View", permissions);
    }

    [Fact]
    public async Task SetPermissionsAsync_ShouldAddAndRemovePermissions()
    {
        await using var fixture = await CreateFixtureAsync();

        var roleId = await AddRoleAsync(fixture.Context);
        var store = CreateStore(fixture.Context);

        await store.GrantAsync(
            roleId,
            "Products.View");

        await store.GrantAsync(
            roleId,
            "Products.Create");

        await store.SetPermissionsAsync(
            roleId,
            ["Products.Create", "Products.Edit"]);

        var permissions =
            await store.GetPermissionsAsync(roleId);

        Assert.Equal(2, permissions.Count);
        Assert.Contains("Products.Create", permissions);
        Assert.Contains("Products.Edit", permissions);
        Assert.DoesNotContain("Products.View", permissions);
    }

    [Fact]
    public async Task SetPermissionsAsync_ShouldLeaveUnchangedPermissionsIntact()
    {
        await using var fixture = await CreateFixtureAsync();

        var roleId = await AddRoleAsync(fixture.Context);
        var store = CreateStore(fixture.Context);

        await store.SetPermissionsAsync(
            roleId,
            ["Products.View", "Products.Edit"]);

        await store.SetPermissionsAsync(
            roleId,
            ["Products.View", "Products.Edit"]);

        var permissions =
            await store.GetPermissionsAsync(roleId);

        Assert.Equal(2, permissions.Count);
        Assert.Contains("Products.View", permissions);
        Assert.Contains("Products.Edit", permissions);
    }

    [Fact]
    public async Task SetPermissionsAsync_ShouldRemoveAllPermissions_WhenCollectionIsEmpty()
    {
        await using var fixture = await CreateFixtureAsync();

        var roleId = await AddRoleAsync(fixture.Context);
        var store = CreateStore(fixture.Context);

        await store.SetPermissionsAsync(
            roleId,
            ["Products.View", "Products.Edit"]);

        await store.SetPermissionsAsync(
            roleId,
            []);

        var permissions =
            await store.GetPermissionsAsync(roleId);

        Assert.Empty(permissions);
    }

    [Fact]
    public async Task SetPermissionsAsync_ShouldNotCreateDuplicates_WhenInputContainsDuplicates()
    {
        await using var fixture = await CreateFixtureAsync();

        var roleId = await AddRoleAsync(fixture.Context);
        var store = CreateStore(fixture.Context);

        await store.SetPermissionsAsync(
            roleId,
            [
                "Products.View",
                "Products.View",
                "Products.Edit"
            ]);

        var permissions =
            await store.GetPermissionsAsync(roleId);

        Assert.Equal(2, permissions.Count);
        Assert.Contains("Products.View", permissions);
        Assert.Contains("Products.Edit", permissions);
    }

    private static RolePermissionGrantStore<
        TestDbContext,
        Guid> CreateStore(
            TestDbContext context)
    {
        return new RolePermissionGrantStore<
            TestDbContext,
            Guid>(context);
    }

    private static async Task<Guid> AddRoleAsync(
        TestDbContext context)
    {
        var role = new TestRole
        {
            Id = Guid.NewGuid(),
            Name = Guid.NewGuid().ToString(),
            NormalizedName = Guid.NewGuid()
                .ToString()
                .ToUpperInvariant()
        };

        context.Roles.Add(role);

        await context.SaveChangesAsync();

        return role.Id;
    }

    private static async Task<TestFixture>
        CreateFixtureAsync()
    {
        var connection =
            new SqliteConnection("Data Source=:memory:");

        await connection.OpenAsync();

        var options =
            new DbContextOptionsBuilder<TestDbContext>()
                .UseSqlite(connection)
                .Options;

        var context =
            new TestDbContext(options);

        await context.Database.EnsureCreatedAsync();

        return new TestFixture(
            connection,
            context);
    }

    private sealed class TestUser
        : IdentityUser<Guid>
    {
    }

    private sealed class TestRole
        : IdentityRole<Guid>
    {
    }

    private sealed class TestDbContext
        : IdentityDbContext<
            TestUser,
            TestRole,
            Guid>
    {
        public TestDbContext(
            DbContextOptions<TestDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(
            ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.ConfigureBehrouzanAuth<
                TestUser,
                TestRole,
                Guid>();
        }
    }

    private sealed class TestFixture
        : IAsyncDisposable
    {
        public TestFixture(
            SqliteConnection connection,
            TestDbContext context)
        {
            Connection = connection;
            Context = context;
        }

        public SqliteConnection Connection { get; }

        public TestDbContext Context { get; }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }
}