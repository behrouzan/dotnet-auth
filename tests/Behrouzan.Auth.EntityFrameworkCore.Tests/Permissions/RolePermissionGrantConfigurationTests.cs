using Behrouzan.Auth.EntityFrameworkCore.Extensions;
using Behrouzan.Auth.EntityFrameworkCore.Permissions;
using Microsoft.EntityFrameworkCore;

namespace Behrouzan.Auth.EntityFrameworkCore.Tests.Permissions;

public sealed class RolePermissionGrantConfigurationTests
{
    [Fact]
    public void ConfigureBehrouzanAuth_ShouldConfigureRolePermissionGrant()
    {
        using var context =
            new TestDbContext(
                new DbContextOptionsBuilder<TestDbContext>()
                    .UseInMemoryDatabase("AuthModelTest")
                    .Options);

        var entityType =
            context.Model.FindEntityType(
                typeof(RolePermissionGrant<Guid>));

        Assert.NotNull(entityType);

        var primaryKey =
            entityType.FindPrimaryKey();

        Assert.NotNull(primaryKey);

        Assert.Equal(
            ["RoleId", "PermissionName"],
            primaryKey.Properties
                .Select(property => property.Name)
                .ToArray());

        var permissionName =
            entityType.FindProperty("PermissionName");

        Assert.NotNull(permissionName);
        Assert.Equal(
            256,
            permissionName.GetMaxLength());
    }

    private sealed class TestDbContext
        : DbContext
    {
        public TestDbContext(
            DbContextOptions<TestDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(
            ModelBuilder modelBuilder)
        {
            modelBuilder.ConfigureBehrouzanAuth<Guid>();
        }
    }
}