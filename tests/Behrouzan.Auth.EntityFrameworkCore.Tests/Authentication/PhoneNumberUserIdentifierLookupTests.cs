using Behrouzan.Auth.Authentication;
using Behrouzan.Auth.EntityFrameworkCore.DependencyInjection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Behrouzan.Auth.EntityFrameworkCore.Tests.Authentication;

public sealed class PhoneNumberUserIdentifierLookupTests
{
    [Fact]
    public async Task FindAsync_ShouldReturnEveryUserWithMatchingPhoneNumber()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        var options = new DbContextOptionsBuilder<TestDbContext>()
            .UseSqlite(connection)
            .Options;

        await using var context = new TestDbContext(options);
        await context.Database.EnsureCreatedAsync();

        var first = new TestUser { Id = Guid.NewGuid(), UserName = "first", PhoneNumber = "+15551234567" };
        var second = new TestUser { Id = Guid.NewGuid(), UserName = "second", PhoneNumber = "+15551234567" };
        context.Users.AddRange(first, second);
        await context.SaveChangesAsync();

        var services = new ServiceCollection();
        services.AddDbContext<TestDbContext>(
            builder => builder.UseSqlite(connection));
        services.AddBehrouzanAuthEntityFrameworkCore<
            TestDbContext,
            TestUser,
            TestRole,
            Guid>();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var lookup = scope.ServiceProvider.GetRequiredService<
            IUserIdentifierLookup<TestUser>>();

        var users = await lookup.FindAsync("+15551234567");

        Assert.Equal(UserIdentifierType.PhoneNumber, lookup.IdentifierType);
        Assert.Equal(2, users.Count);
        Assert.Contains(users, user => user.Id == first.Id);
        Assert.Contains(users, user => user.Id == second.Id);
    }

    private sealed class TestUser : IdentityUser<Guid> { }
    private sealed class TestRole : IdentityRole<Guid> { }

    private sealed class TestDbContext
        : IdentityDbContext<TestUser, TestRole, Guid>
    {
        public TestDbContext(DbContextOptions<TestDbContext> options) : base(options) { }
    }
}
