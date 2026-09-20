using System.Security.Claims;
using Behrouzan.Auth.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Behrouzan.Auth.AspNetCore.Tests.Authentication;

public sealed class PasswordSignInManagerTests
{
    [Fact]
    public async Task SignInAsync_ShouldReturnInvalidCredentials_WhenUserIsNotResolved()
    {
        var userResolver =
            new TestUserSignInResolver(
                UserSignInResolution<TestUser>.NotFound());

        var signInManager =
            CreateSignInManager();

        var manager =
            CreateManager(
                userResolver,
                signInManager);

        var result =
            await manager.SignInAsync(
                "unknown-user",
                "password");

        Assert.False(result.IsSuccess);

        Assert.Equal(
            PasswordSignInErrorCode.InvalidCredentials,
            result.ErrorCode);

        Assert.Equal(
            0,
            signInManager.PasswordSignInCallCount);
    }

    [Fact]
    public async Task SignInAsync_ShouldReturnInvalidCredentials_WhenResolutionIsAmbiguous()
    {
        var userResolver =
            new TestUserSignInResolver(
                UserSignInResolution<TestUser>.Ambiguous());

        var signInManager =
            CreateSignInManager();

        var manager =
            CreateManager(
                userResolver,
                signInManager);

        var result =
            await manager.SignInAsync(
                "ambiguous",
                "password");

        Assert.False(result.IsSuccess);

        Assert.Equal(
            PasswordSignInErrorCode.InvalidCredentials,
            result.ErrorCode);

        Assert.Equal(
            0,
            signInManager.PasswordSignInCallCount);
    }

    [Fact]
    public async Task SignInAsync_ShouldReturnSuccess_WhenIdentitySignInSucceeds()
    {
        var user =
            new TestUser
            {
                Id = Guid.NewGuid()
            };

        var userResolver =
            new TestUserSignInResolver(
                UserSignInResolution<TestUser>.Resolved(user));

        var signInManager =
            CreateSignInManager(
                SignInResult.Success);

        var manager =
            CreateManager(
                userResolver,
                signInManager);

        var result =
            await manager.SignInAsync(
                "behzad",
                "correct-password");

        Assert.True(result.IsSuccess);
        Assert.Null(result.ErrorCode);

        Assert.Equal(
            1,
            signInManager.PasswordSignInCallCount);
    }


    [Fact]
    public async Task SignInAsync_ShouldReturnInvalidCredentials_WhenIdentitySignInFails()
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid()
        };

        var userResolver =
            new TestUserSignInResolver(
                UserSignInResolution<TestUser>.Resolved(user));

        var signInManager =
            CreateSignInManager(
                SignInResult.Failed);

        var manager =
            CreateManager(
                userResolver,
                signInManager);

        var result =
            await manager.SignInAsync(
                "behzad",
                "wrong-password");

        Assert.False(result.IsSuccess);

        Assert.Equal(
            PasswordSignInErrorCode.InvalidCredentials,
            result.ErrorCode);
    }

    [Fact]
    public async Task SignInAsync_ShouldReturnLockedOut_WhenIdentityReportsLockedOut()
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid()
        };

        var userResolver =
            new TestUserSignInResolver(
                UserSignInResolution<TestUser>.Resolved(user));

        var signInManager =
            CreateSignInManager(
                SignInResult.LockedOut);

        var manager =
            CreateManager(
                userResolver,
                signInManager);

        var result =
            await manager.SignInAsync(
                "behzad",
                "password");

        Assert.False(result.IsSuccess);

        Assert.Equal(
            PasswordSignInErrorCode.LockedOut,
            result.ErrorCode);
    }

    [Fact]
    public async Task SignInAsync_ShouldReturnRequiresTwoFactor_WhenIdentityRequiresTwoFactor()
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid()
        };

        var userResolver =
            new TestUserSignInResolver(
                UserSignInResolution<TestUser>.Resolved(user));

        var signInManager =
            CreateSignInManager(
                SignInResult.TwoFactorRequired);

        var manager =
            CreateManager(
                userResolver,
                signInManager);

        var result =
            await manager.SignInAsync(
                "behzad",
                "password");

        Assert.False(result.IsSuccess);

        Assert.Equal(
            PasswordSignInErrorCode.RequiresTwoFactor,
            result.ErrorCode);
    }

    [Fact]
    public async Task SignInAsync_ShouldReturnNotAllowed_WhenIdentityReportsNotAllowed()
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid()
        };

        var userResolver =
            new TestUserSignInResolver(
                UserSignInResolution<TestUser>.Resolved(user));

        var signInManager =
            CreateSignInManager(
                SignInResult.NotAllowed);

        var manager =
            CreateManager(
                userResolver,
                signInManager);

        var result =
            await manager.SignInAsync(
                "behzad",
                "password");

        Assert.False(result.IsSuccess);

        Assert.Equal(
            PasswordSignInErrorCode.NotAllowed,
            result.ErrorCode);
    }


    [Fact]
    public async Task SignInAsync_ShouldUseConfiguredLockoutOnFailure()
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid()
        };

        var userResolver =
            new TestUserSignInResolver(
                UserSignInResolution<TestUser>.Resolved(user));

        var signInManager =
            CreateSignInManager(
                SignInResult.Success);

        var manager =
            CreateManager(
                userResolver,
                signInManager,
                lockoutOnFailure: false);

        await manager.SignInAsync(
            "behzad",
            "password");

        Assert.False(
            signInManager.LastLockoutOnFailure);
    }

    [Fact]
    public async Task SignInAsync_ShouldPassIsPersistentToIdentity()
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid()
        };

        var userResolver =
            new TestUserSignInResolver(
                UserSignInResolution<TestUser>.Resolved(user));

        var signInManager =
            CreateSignInManager(
                SignInResult.Success);

        var manager =
            CreateManager(
                userResolver,
                signInManager);

        await manager.SignInAsync(
            "behzad",
            "password",
            isPersistent: true);

        Assert.True(
            signInManager.LastIsPersistent);
    }


    private static PasswordSignInManager<TestUser> CreateManager(
        IUserSignInResolver<TestUser> userResolver,
        TestSignInManager signInManager,
        bool lockoutOnFailure = true)
    {
        var options =
            Options.Create(
                new PasswordSignInOptions
                {
                    LockoutOnFailure =
                        lockoutOnFailure
                });

        return new PasswordSignInManager<TestUser>(
            userResolver,
            signInManager,
            options);
    }

    private static TestSignInManager CreateSignInManager(
        SignInResult? result = null)
    {
        return new TestSignInManager(
            result ?? SignInResult.Failed);
    }

    private sealed class TestUser
        : IdentityUser<Guid>
    {
    }

    private sealed class TestUserSignInResolver
        : IUserSignInResolver<TestUser>
    {
        private readonly UserSignInResolution<TestUser>
            _resolution;

        public TestUserSignInResolver(
            UserSignInResolution<TestUser> resolution)
        {
            _resolution = resolution;
        }

        public Task<UserSignInResolution<TestUser>> ResolveAsync(
            string identifier,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(
                _resolution);
        }
    }

    private sealed class TestSignInManager
        : SignInManager<TestUser>
    {
        private readonly SignInResult _result;
        public bool? LastLockoutOnFailure
        {
            get;
            private set;
        }

        public bool? LastIsPersistent
        {
            get;
            private set;
        }
        public TestSignInManager(
            SignInResult result)
            : base(
                new TestUserManager(),
                new HttpContextAccessor(),
                new TestClaimsPrincipalFactory(),
                Microsoft.Extensions.Options.Options.Create(
                    new IdentityOptions()),
                NullLogger<SignInManager<TestUser>>.Instance,
                new AuthenticationSchemeProvider(
                    Microsoft.Extensions.Options.Options.Create(
                        new AuthenticationOptions())),
                new DefaultUserConfirmation<TestUser>())
        {
            _result = result;
        }

        public int PasswordSignInCallCount
        {
            get;
            private set;
        }

        public override Task<SignInResult> PasswordSignInAsync(
            TestUser user,
            string password,
            bool isPersistent,
            bool lockoutOnFailure)
        {
            PasswordSignInCallCount++;
            LastIsPersistent = isPersistent;
            LastLockoutOnFailure = lockoutOnFailure;

            return Task.FromResult(
                _result);
        }
    }

    private sealed class TestUserManager
        : UserManager<TestUser>
    {
        public TestUserManager()
            : base(
                new TestUserStore(),
                Microsoft.Extensions.Options.Options.Create(
                    new IdentityOptions()),
                new PasswordHasher<TestUser>(),
                Array.Empty<IUserValidator<TestUser>>(),
                Array.Empty<IPasswordValidator<TestUser>>(),
                new UpperInvariantLookupNormalizer(),
                new IdentityErrorDescriber(),
                null!,
                NullLogger<UserManager<TestUser>>.Instance)
        {
        }
    }

    private sealed class TestUserStore
        : IUserStore<TestUser>
    {
        public void Dispose()
        {
        }

        public Task<string> GetUserIdAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                user.Id.ToString());
        }

        public Task<string?> GetUserNameAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                user.UserName);
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
            user.NormalizedUserName = normalizedName;

            return Task.CompletedTask;
        }

        public Task<IdentityResult> CreateAsync(
            TestUser user,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                IdentityResult.Success);
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
            return Task.FromResult(
                IdentityResult.Success);
        }

        public Task<TestUser?> FindByIdAsync(
            string userId,
            CancellationToken cancellationToken)
        {
            return Task.FromResult<TestUser?>(
                null);
        }

        public Task<TestUser?> FindByNameAsync(
            string normalizedUserName,
            CancellationToken cancellationToken)
        {
            return Task.FromResult<TestUser?>(
                null);
        }
    }

    private sealed class TestClaimsPrincipalFactory
        : IUserClaimsPrincipalFactory<TestUser>
    {
        public Task<ClaimsPrincipal> CreateAsync(
            TestUser user)
        {
            return Task.FromResult(
                new ClaimsPrincipal(
                    new ClaimsIdentity()));
        }
    }


}