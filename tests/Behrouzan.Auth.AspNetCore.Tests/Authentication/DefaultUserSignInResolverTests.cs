using Behrouzan.Auth.AspNetCore.Authentication;
using Behrouzan.Auth.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Behrouzan.Auth.AspNetCore.Tests.Authentication;

public sealed class DefaultUserSignInResolverTests
{
    [Fact]
    public async Task ResolveAsync_ShouldResolveUserByUserName()
    {
        using var provider = CreateServiceProvider(
            SignInIdentifier.UserName);

        await using var scope = provider.CreateAsyncScope();

        var userManager =
            scope.ServiceProvider
                .GetRequiredService<UserManager<TestUser>>();

        var user = new TestUser
        {
            UserName = "behzad"
        };

        var createResult =
            await userManager.CreateAsync(user);

        Assert.True(createResult.Succeeded);

        var resolver =
            CreateResolver(
                userManager,
                SignInIdentifier.UserName);

        var result =
            await resolver.ResolveAsync("behzad");

        Assert.Equal(
            UserSignInResolutionStatus.Resolved,
            result.Status);

        Assert.NotNull(result.User);
        Assert.Equal(user.Id, result.User.Id);
    }

    [Fact]
    public async Task ResolveAsync_ShouldResolveUserByEmail()
    {
        using var provider = CreateServiceProvider(
            SignInIdentifier.Email);

        await using var scope = provider.CreateAsyncScope();

        var userManager =
            scope.ServiceProvider
                .GetRequiredService<UserManager<TestUser>>();

        var user = new TestUser
        {
            UserName = "behzad",
            Email = "behzad@example.com"
        };

        var createResult =
            await userManager.CreateAsync(user);

        Assert.True(createResult.Succeeded);

        var resolver =
            CreateResolver(
                userManager,
                SignInIdentifier.Email);

        var result =
            await resolver.ResolveAsync(
                "behzad@example.com");

        Assert.Equal(
            UserSignInResolutionStatus.Resolved,
            result.Status);

        Assert.NotNull(result.User);
        Assert.Equal(user.Id, result.User.Id);
    }

    [Fact]
    public async Task ResolveAsync_ShouldReturnNotFound_WhenNoUserMatches()
    {
        using var provider = CreateServiceProvider(
            SignInIdentifier.UserName |
            SignInIdentifier.Email);

        await using var scope = provider.CreateAsyncScope();

        var userManager =
            scope.ServiceProvider
                .GetRequiredService<UserManager<TestUser>>();

        var resolver =
            CreateResolver(
                userManager,
                SignInIdentifier.UserName |
                SignInIdentifier.Email);

        var result =
            await resolver.ResolveAsync(
                "missing@example.com");

        Assert.Equal(
            UserSignInResolutionStatus.NotFound,
            result.Status);

        Assert.Null(result.User);
    }


    [Fact]
    public async Task ResolveAsync_ShouldReturnAmbiguous_WhenDifferentUsersMatchDifferentIdentifiers()
    {
        using var provider = CreateServiceProvider(
            SignInIdentifier.UserName |
            SignInIdentifier.Email);

        await using var scope = provider.CreateAsyncScope();

        var userManager =
            scope.ServiceProvider
                .GetRequiredService<UserManager<TestUser>>();

        var userNameUser = new TestUser
        {
            Id = Guid.NewGuid(),
            UserName = "behzad@example.com"
        };

        var emailUser = new TestUser
        {
            Id = Guid.NewGuid(),
            UserName = "another-user",
            Email = "behzad@example.com"
        };

        var firstCreateResult =
            await userManager.CreateAsync(userNameUser);

        var secondCreateResult =
            await userManager.CreateAsync(emailUser);

        Assert.True(firstCreateResult.Succeeded);
        Assert.True(secondCreateResult.Succeeded);

        var resolver =
            CreateResolver(
                userManager,
                SignInIdentifier.UserName |
                SignInIdentifier.Email);

        var result =
            await resolver.ResolveAsync(
                "behzad@example.com");

        Assert.Equal(
            UserSignInResolutionStatus.Ambiguous,
            result.Status);

        Assert.Null(result.User);
    }


    [Fact]
    public async Task ResolveAsync_ShouldResolve_WhenUserNameAndEmailMatchSameUser()
    {
        using var provider = CreateServiceProvider(
            SignInIdentifier.UserName |
            SignInIdentifier.Email);

        await using var scope = provider.CreateAsyncScope();

        var userManager =
            scope.ServiceProvider
                .GetRequiredService<UserManager<TestUser>>();

        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            UserName = "behzad@example.com",
            Email = "behzad@example.com"
        };

        var createResult =
            await userManager.CreateAsync(user);

        Assert.True(createResult.Succeeded);

        var resolver =
            CreateResolver(
                userManager,
                SignInIdentifier.UserName |
                SignInIdentifier.Email);

        var result =
            await resolver.ResolveAsync(
                "behzad@example.com");

        Assert.Equal(
            UserSignInResolutionStatus.Resolved,
            result.Status);

        Assert.NotNull(result.User);

        Assert.Equal(
            user.Id,
            result.User.Id);
    }

    [Fact]
    public async Task ResolveAsync_ShouldResolveUserByPhoneNumber()
    {
        using var provider = CreateServiceProvider(SignInIdentifier.PhoneNumber);
        await using var scope = provider.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestUser>>();
        var user = new TestUser { UserName = "behzad", PhoneNumber = "+15551234567" };
        Assert.True((await userManager.CreateAsync(user)).Succeeded);

        var result = await CreateResolver(
            userManager,
            SignInIdentifier.PhoneNumber,
            new TestIdentifierLookup(user)).ResolveAsync(user.PhoneNumber!);

        Assert.Equal(UserSignInResolutionStatus.Resolved, result.Status);
        Assert.Equal(user.Id, result.User!.Id);
    }

    [Fact]
    public async Task ResolveAsync_ShouldReturnNotFound_WhenPhoneNumberDoesNotMatch()
    {
        using var provider = CreateServiceProvider(SignInIdentifier.PhoneNumber);
        await using var scope = provider.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestUser>>();

        var result = await CreateResolver(
            userManager,
            SignInIdentifier.PhoneNumber,
            null).ResolveAsync("+15551234567");

        Assert.Equal(UserSignInResolutionStatus.NotFound, result.Status);
    }

    [Fact]
    public async Task ResolveAsync_ShouldReturnAmbiguous_WhenPhoneNumberMatchesMultipleUsers()
    {
        using var provider = CreateServiceProvider(SignInIdentifier.PhoneNumber);
        await using var scope = provider.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestUser>>();
        var first = new TestUser { UserName = "first" };
        var second = new TestUser { UserName = "second" };
        Assert.True((await userManager.CreateAsync(first)).Succeeded);
        Assert.True((await userManager.CreateAsync(second)).Succeeded);

        var result = await CreateResolver(
            userManager,
            SignInIdentifier.PhoneNumber,
            new TestIdentifierLookup(first, second)).ResolveAsync("+15551234567");

        Assert.Equal(UserSignInResolutionStatus.Ambiguous, result.Status);
    }

    [Fact]
    public async Task ResolveAsync_ShouldReturnAmbiguous_WhenUserNameAndPhoneNumberMatchDifferentUsers()
    {
        using var provider = CreateServiceProvider(
            SignInIdentifier.UserName | SignInIdentifier.PhoneNumber);
        await using var scope = provider.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestUser>>();
        var userNameUser = new TestUser { UserName = "identifier" };
        var phoneUser = new TestUser { UserName = "phone-user" };
        Assert.True((await userManager.CreateAsync(userNameUser)).Succeeded);
        Assert.True((await userManager.CreateAsync(phoneUser)).Succeeded);

        var result = await CreateResolver(
            userManager,
            SignInIdentifier.UserName | SignInIdentifier.PhoneNumber,
            new TestIdentifierLookup(phoneUser)).ResolveAsync("identifier");

        Assert.Equal(UserSignInResolutionStatus.Ambiguous, result.Status);
    }

    [Fact]
    public async Task ResolveAsync_ShouldResolve_WhenUserNameAndPhoneNumberMatchSameUser()
    {
        using var provider = CreateServiceProvider(
            SignInIdentifier.UserName | SignInIdentifier.PhoneNumber);
        await using var scope = provider.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestUser>>();
        var user = new TestUser { UserName = "identifier" };
        Assert.True((await userManager.CreateAsync(user)).Succeeded);

        var result = await CreateResolver(
            userManager,
            SignInIdentifier.UserName | SignInIdentifier.PhoneNumber,
            new TestIdentifierLookup(user)).ResolveAsync("identifier");

        Assert.Equal(UserSignInResolutionStatus.Resolved, result.Status);
        Assert.Equal(user.Id, result.User!.Id);
    }


    private static DefaultUserSignInResolver<TestUser>
        CreateResolver(
            UserManager<TestUser> userManager,
            SignInIdentifier allowedIdentifiers,
            IUserIdentifierLookup<TestUser>? identifierLookup = null)
    {
        var options =
            Options.Create(
                new PasswordSignInOptions
                {
                    AllowedIdentifiers =
                        allowedIdentifiers
                });

        return new DefaultUserSignInResolver<TestUser>(
            userManager,
            options,
            identifierLookup);
    }

    private static ServiceProvider CreateServiceProvider(
        SignInIdentifier allowedIdentifiers)
    {
        var services =
            new ServiceCollection();

        services.AddLogging();

        //services.AddSingleton<InMemoryUserStore>();
        services
            .AddIdentityCore<TestUser>()
            .AddUserStore<InMemoryUserStore>();

        //services.AddSingleton<IUserStore<TestUser>, InMemoryUserStore>();

        services.Configure<PasswordSignInOptions>(
            options =>
            {
                options.AllowedIdentifiers =
                    allowedIdentifiers;
            });

        return services.BuildServiceProvider();
    }

    private sealed class TestUser
        : IdentityUser<Guid>
    {
    }

    private sealed class InMemoryUserStore :
        IUserStore<TestUser>,
        IUserEmailStore<TestUser>
    {
        private readonly List<TestUser> _users = [];

        public Task<IdentityResult> CreateAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            if (user.Id == Guid.Empty)
            {
                user.Id = Guid.NewGuid();
            }

            _users.Add(user);

            return Task.FromResult(
                IdentityResult.Success);
        }
        public Task<TestUser?> FindByIdAsync(
            string userId,
            CancellationToken cancellationToken)
        {
            var id = Guid.Parse(userId);

            return Task.FromResult(
                _users.SingleOrDefault(
                    user => user.Id == id));
        }

        public Task<TestUser?> FindByNameAsync(
            string normalizedUserName,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                _users.SingleOrDefault(
                    user =>
                        user.NormalizedUserName ==
                        normalizedUserName));
        }

        public Task<TestUser?> FindByEmailAsync(
            string normalizedEmail,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                _users.SingleOrDefault(
                    user =>
                        user.NormalizedEmail ==
                        normalizedEmail));
        }

        public Task<string?> GetUserNameAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserName);
        }

        public Task SetUserNameAsync(
            TestUser user,
            string? userName,
            CancellationToken cancellationToken)
        {
            user.UserName = userName;
            return Task.CompletedTask;
        }

        public Task<string?> GetNormalizedUserNameAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                user.NormalizedUserName);
        }

        public Task SetNormalizedUserNameAsync(
            TestUser user,
            string? normalizedName,
            CancellationToken cancellationToken)
        {
            user.NormalizedUserName =
                normalizedName;

            return Task.CompletedTask;
        }

        public Task<string?> GetEmailAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Email);
        }

        public Task SetEmailAsync(
            TestUser user,
            string? email,
            CancellationToken cancellationToken)
        {
            user.Email = email;
            return Task.CompletedTask;
        }

        public Task<bool> GetEmailConfirmedAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                user.EmailConfirmed);
        }

        public Task SetEmailConfirmedAsync(
            TestUser user,
            bool confirmed,
            CancellationToken cancellationToken)
        {
            user.EmailConfirmed = confirmed;
            return Task.CompletedTask;
        }

        public Task<string?> GetNormalizedEmailAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                user.NormalizedEmail);
        }

        public Task SetNormalizedEmailAsync(
            TestUser user,
            string? normalizedEmail,
            CancellationToken cancellationToken)
        {
            user.NormalizedEmail =
                normalizedEmail;

            return Task.CompletedTask;
        }

        public Task<IdentityResult> UpdateAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                IdentityResult.Success);
        }

        public Task<IdentityResult> DeleteAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            _users.Remove(user);

            return Task.FromResult(
                IdentityResult.Success);
        }

        public Task<string> GetUserIdAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                user.Id.ToString());
        }

        public void Dispose()
        {
        }
    }

    private sealed class TestIdentifierLookup
        : IUserIdentifierLookup<TestUser>
    {
        private readonly IReadOnlyCollection<TestUser> _users;

        public TestIdentifierLookup(params TestUser[] users)
        {
            _users = users;
        }

        public UserIdentifierType IdentifierType => UserIdentifierType.PhoneNumber;

        public Task<IReadOnlyCollection<TestUser>> FindAsync(
            string identifier,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_users);
        }
    }
}
