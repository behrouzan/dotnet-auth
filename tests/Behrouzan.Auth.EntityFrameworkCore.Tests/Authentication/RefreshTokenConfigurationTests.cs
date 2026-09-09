using Behrouzan.Auth.EntityFrameworkCore.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Behrouzan.Auth.EntityFrameworkCore.Tests.Authentication;

public sealed class RefreshTokenConfigurationTests
{
    [Fact]
    public void ConfigureBehrouzanAuth_ShouldConfigureRefreshTokenHash()
    {
        var options =
    new DbContextOptionsBuilder<TestDbContext>()
        .UseInMemoryDatabase(Guid.NewGuid().ToString())
        .Options;

        using var context = new TestDbContext(options);

        var entityType = context.Model
            .GetEntityTypes()
            .Single(entity =>
                entity.ClrType.Name.StartsWith(
                    "RefreshToken",
                    StringComparison.Ordinal));

        var tokenHash =
            entityType.FindProperty("TokenHash");

        Assert.NotNull(tokenHash);
        Assert.False(tokenHash.IsNullable);
        Assert.Equal(32, tokenHash.GetMaxLength());

        var uniqueIndex = entityType
            .GetIndexes()
            .SingleOrDefault(index =>
                index.IsUnique &&
                index.Properties.Count == 1 &&
                index.Properties[0].Name == "TokenHash");

        Assert.NotNull(uniqueIndex);
    }

    private sealed class TestUser : IdentityUser<Guid>
    {
    }

    private sealed class TestRole : IdentityRole<Guid>
    {
    }

    private sealed class TestDbContext
        : IdentityDbContext<TestUser, TestRole, Guid>
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
}