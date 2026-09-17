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
}