using Behrouzan.Auth.Authentication;
using Behrouzan.Auth.Permissions;
using Behrouzan.Auth.EntityFrameworkCore.DependencyInjection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Behrouzan.Auth.EntityFrameworkCore.Tests.DependencyInjection;

public sealed class ServiceCollectionExtensionsTests
{
    [Fact]
    public void AddBehrouzanAuthEntityFrameworkCore_ShouldRegisterRefreshTokenStore()
    {
        var services = new ServiceCollection();

        services.AddDbContext<TestDbContext>(
            options =>
                options.UseInMemoryDatabase(
                    Guid.NewGuid().ToString()));

        services.AddBehrouzanAuthEntityFrameworkCore<
            TestDbContext,
            TestUser,
            TestRole,
            Guid>();

        using var provider =
            services.BuildServiceProvider();

        using var scope =
            provider.CreateScope();

        var store =
            scope.ServiceProvider
                .GetService<IRefreshTokenStore<Guid>>();

        Assert.NotNull(store);
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
    }

    [Fact]
    public void AddBehrouzanAuthEntityFrameworkCore_ShouldRegisterRolePermissionGrantStore()
    {
        var services = new ServiceCollection();

        services.AddDbContext<TestDbContext>(
            options =>
                options.UseInMemoryDatabase(
                    Guid.NewGuid().ToString()));

        services.AddBehrouzanAuthEntityFrameworkCore<
            TestDbContext,
            TestUser,
            TestRole,
            Guid>();

        using var provider =
            services.BuildServiceProvider();

        using var scope =
            provider.CreateScope();

        var store =
            scope.ServiceProvider
                .GetService<IRolePermissionGrantStore<Guid>>();

        Assert.NotNull(store);
    }

    [Fact]
    public void AddBehrouzanAuthEntityFrameworkCore_ShouldRegisterPhoneNumberIdentifierLookup()
    {
        var services = new ServiceCollection();

        services.AddDbContext<TestDbContext>(
            options => options.UseInMemoryDatabase(Guid.NewGuid().ToString()));

        services.AddBehrouzanAuthEntityFrameworkCore<
            TestDbContext,
            TestUser,
            TestRole,
            Guid>();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var lookup = scope.ServiceProvider.GetRequiredService<
            IUserIdentifierLookup<TestUser>>();

        Assert.Equal(UserIdentifierType.PhoneNumber, lookup.IdentifierType);
    }

    [Fact]
    public void AddBehrouzanAuthEntityFrameworkCore_ShouldNotDuplicatePhoneNumberIdentifierLookup()
    {
        var services = new ServiceCollection();

        services.AddDbContext<TestDbContext>(
            options => options.UseInMemoryDatabase(Guid.NewGuid().ToString()));

        services.AddBehrouzanAuthEntityFrameworkCore<
            TestDbContext,
            TestUser,
            TestRole,
            Guid>();
        services.AddBehrouzanAuthEntityFrameworkCore<
            TestDbContext,
            TestUser,
            TestRole,
            Guid>();

        Assert.Single(
            services,
            descriptor => descriptor.ServiceType ==
                typeof(IUserIdentifierLookup<TestUser>));
    }

    [Fact]
    public void AddBehrouzanAuthEntityFrameworkCore_ShouldPreserveCustomIdentifierLookup()
    {
        var services = new ServiceCollection();

        services.AddDbContext<TestDbContext>(
            options => options.UseInMemoryDatabase(Guid.NewGuid().ToString()));
        services.AddScoped<IUserIdentifierLookup<TestUser>, CustomIdentifierLookup>();

        services.AddBehrouzanAuthEntityFrameworkCore<
            TestDbContext,
            TestUser,
            TestRole,
            Guid>();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        var lookup = scope.ServiceProvider.GetRequiredService<
            IUserIdentifierLookup<TestUser>>();

        Assert.IsType<CustomIdentifierLookup>(lookup);
    }

    private sealed class CustomIdentifierLookup : IUserIdentifierLookup<TestUser>
    {
        public UserIdentifierType IdentifierType => UserIdentifierType.PhoneNumber;

        public Task<IReadOnlyCollection<TestUser>> FindAsync(
            string identifier,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyCollection<TestUser>>([]);
        }
    }
}
