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

    [Fact]
    public async Task AuthenticateAsync_ShouldReturnResolvedUser_WhenPasswordIsCorrect()
    {
        var user = new TestUser { Id = Guid.NewGuid() };
        var signInManager = CreateSignInManager(SignInResult.Success);

        var result = await CreateAuthenticationManager(
            new TestUserSignInResolver(UserSignInResolution<TestUser>.Resolved(user)),
            signInManager).AuthenticateAsync("behzad", "correct-password");

        Assert.True(result.IsSuccess);
        Assert.Same(user, result.User);
        Assert.Null(result.ErrorCode);
        Assert.Equal(1, signInManager.CheckPasswordSignInCallCount);
        Assert.Equal(0, signInManager.PasswordSignInCallCount);
    }

    [Theory]
    [InlineData(UserSignInResolutionStatus.NotFound)]
    [InlineData(UserSignInResolutionStatus.Ambiguous)]
    public async Task AuthenticateAsync_ShouldReturnInvalidCredentials_WhenUserIsNotUniquelyResolved(
        UserSignInResolutionStatus status)
    {
        var resolution = status == UserSignInResolutionStatus.NotFound
            ? UserSignInResolution<TestUser>.NotFound()
            : UserSignInResolution<TestUser>.Ambiguous();
        var signInManager = CreateSignInManager();

        var result = await CreateAuthenticationManager(
            new TestUserSignInResolver(resolution), signInManager)
            .AuthenticateAsync("identifier", "password");

        Assert.False(result.IsSuccess);
        Assert.Null(result.User);
        Assert.Equal(PasswordAuthenticationErrorCode.InvalidCredentials, result.ErrorCode);
        Assert.Equal(0, signInManager.CheckPasswordSignInCallCount);
        Assert.Equal(0, signInManager.PasswordSignInCallCount);
    }

    [Theory]
    [InlineData("failed", PasswordAuthenticationErrorCode.InvalidCredentials)]
    [InlineData("lockedOut", PasswordAuthenticationErrorCode.LockedOut)]
    [InlineData("notAllowed", PasswordAuthenticationErrorCode.NotAllowed)]
    public async Task AuthenticateAsync_ShouldMapIdentityFailure(
        string identityResult,
        PasswordAuthenticationErrorCode expectedErrorCode)
    {
        var user = new TestUser { Id = Guid.NewGuid() };
        var signInResult = identityResult switch
        {
            "lockedOut" => SignInResult.LockedOut,
            "notAllowed" => SignInResult.NotAllowed,
            _ => SignInResult.Failed
        };
        var signInManager = CreateSignInManager(signInResult);

        var result = await CreateAuthenticationManager(
            new TestUserSignInResolver(UserSignInResolution<TestUser>.Resolved(user)),
            signInManager).AuthenticateAsync("behzad", "password");

        Assert.False(result.IsSuccess);
        Assert.Equal(expectedErrorCode, result.ErrorCode);
        Assert.Equal(1, signInManager.CheckPasswordSignInCallCount);
        Assert.Equal(0, signInManager.PasswordSignInCallCount);
    }

    [Fact]
    public async Task AuthenticateAsync_ShouldUseConfiguredLockoutOnFailure()
    {
        var user = new TestUser { Id = Guid.NewGuid() };
        var signInManager = CreateSignInManager(SignInResult.Failed);

        await CreateAuthenticationManager(
            new TestUserSignInResolver(UserSignInResolution<TestUser>.Resolved(user)),
            signInManager,
            lockoutOnFailure: false).AuthenticateAsync("behzad", "password");

        Assert.False(signInManager.LastCheckLockoutOnFailure);
        Assert.Equal(0, signInManager.PasswordSignInCallCount);
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

    private static PasswordAuthenticationManager<TestUser> CreateAuthenticationManager(
        IUserSignInResolver<TestUser> userResolver,
        TestSignInManager signInManager,
        bool lockoutOnFailure = true)
    {
        var options = Options.Create(new PasswordSignInOptions
        {
            LockoutOnFailure = lockoutOnFailure
        });

        return new PasswordAuthenticationManager<TestUser>(
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
        public bool? LastCheckLockoutOnFailure { get; private set; }
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

        public override Task<SignInResult> CheckPasswordSignInAsync(
            TestUser user,
            string password,
            bool lockoutOnFailure)
        {
            CheckPasswordSignInCallCount++;
            LastCheckLockoutOnFailure = lockoutOnFailure;

            return Task.FromResult(_result);
        }

        public int CheckPasswordSignInCallCount { get; private set; }
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
