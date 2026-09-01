using Behrouzan.Auth.EntityFrameworkCore.Extensions;
using Behrouzan.Auth.EntityFrameworkCore.Permissions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Behrouzan.Auth.EntityFrameworkCore.Tests.Permissions;

public sealed class EfPermissionGrantStoreTests
{
    [Fact]
    public async Task GetGrantedPermissionsAsync_ShouldReturnPermissionsFromUserRoles()
    {
        var options =
            new DbContextOptionsBuilder<TestDbContext>()
                .UseInMemoryDatabase(
                    Guid.NewGuid().ToString())
                .Options;

        await using var dbContext =
            new TestDbContext(options);

        var userId = Guid.NewGuid();
        var adminRoleId = Guid.NewGuid();
        var editorRoleId = Guid.NewGuid();

        dbContext.UserRoles.AddRange(
            new IdentityUserRole<Guid>
            {
                UserId = userId,
                RoleId = adminRoleId
            },
            new IdentityUserRole<Guid>
            {
                UserId = userId,
                RoleId = editorRoleId
            });

        dbContext.Set<RolePermissionGrant<Guid>>()
            .AddRange(
                new RolePermissionGrant<Guid>
                {
                    RoleId = adminRoleId,
                    PermissionName = "Products.View"
                },
                new RolePermissionGrant<Guid>
                {
                    RoleId = adminRoleId,
                    PermissionName = "Products.Create"
                },
                new RolePermissionGrant<Guid>
                {
                    RoleId = editorRoleId,
                    PermissionName = "Products.View"
                });

        await dbContext.SaveChangesAsync();

        var store =
            new EfPermissionGrantStore<
                TestDbContext,
                TestUser,
                TestRole,
                Guid>(
                dbContext);

        var permissions =
            await store.GetGrantedPermissionsAsync(
                userId);

        Assert.Equal(
            2,
            permissions.Count);

        Assert.Contains(
            "Products.View",
            permissions);

        Assert.Contains(
            "Products.Create",
            permissions);
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

            builder.ConfigureBehrouzanAuth<Guid>();
        }
    }
}