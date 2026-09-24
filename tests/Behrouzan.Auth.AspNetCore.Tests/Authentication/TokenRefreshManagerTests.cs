using System.Security.Claims;
using System.Text;
using Behrouzan.Auth.AspNetCore.Authentication;
using Behrouzan.Auth.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Behrouzan.Auth.AspNetCore.Tests.Authentication;

public sealed class TokenRefreshManagerTests
{
    [Theory]
    [InlineData(RefreshTokenErrorCodes.InvalidToken, TokenRefreshErrorCode.InvalidToken)]
    [InlineData(RefreshTokenErrorCodes.Expired, TokenRefreshErrorCode.Expired)]
    [InlineData(RefreshTokenErrorCodes.Revoked, TokenRefreshErrorCode.Revoked)]
    [InlineData(RefreshTokenErrorCodes.ReuseDetected, TokenRefreshErrorCode.ReuseDetected)]
    public async Task RefreshAsync_ShouldPreserveValidationErrors(
        string refreshError,
        TokenRefreshErrorCode expectedError)
    {
        var fixture = CreateFixture();
        fixture.RefreshTokens.ValidationResult =
            RefreshTokenValidationResult<Guid>.Failure(refreshError);

        var result = await fixture.Manager.RefreshAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Equal(expectedError, result.ErrorCode);
        Assert.Null(result.AccessToken);
        Assert.Null(result.RefreshToken);
        Assert.Equal(0, fixture.RefreshTokens.RefreshCallCount);
        Assert.Equal(0, fixture.SigningProvider.CallCount);
    }

    [Fact]
    public async Task RefreshAsync_ShouldReturnInvalidToken_WhenOwnerWasDeleted()
    {
        var fixture = CreateFixture(userExists: false);

        var result = await fixture.Manager.RefreshAsync("refresh-token");

        Assert.Equal(TokenRefreshErrorCode.InvalidToken, result.ErrorCode);
        Assert.Equal(0, fixture.RefreshTokens.RefreshCallCount);
        Assert.Equal(0, fixture.SigningProvider.CallCount);
    }

    [Theory]
    [InlineData(true, true, false, TokenRefreshErrorCode.LockedOut)]
    [InlineData(false, false, false, TokenRefreshErrorCode.NotAllowed)]
    [InlineData(false, true, true, TokenRefreshErrorCode.RequiresTwoFactor)]
    public async Task RefreshAsync_ShouldBlockIneligibleUserBeforeIssuance(
        bool lockedOut,
        bool canSignIn,
        bool twoFactorEnabled,
        TokenRefreshErrorCode expectedError)
    {
        var fixture = CreateFixture(
            lockedOut: lockedOut,
            canSignIn: canSignIn,
            twoFactorEnabled: twoFactorEnabled);

        var result = await fixture.Manager.RefreshAsync("refresh-token");

        Assert.Equal(expectedError, result.ErrorCode);
        Assert.Null(result.AccessToken);
        Assert.Null(result.RefreshToken);
        Assert.Equal(0, fixture.RefreshTokens.RefreshCallCount);
        Assert.Equal(0, fixture.SigningProvider.CallCount);
    }

    [Fact]
    public async Task RefreshAsync_ShouldNotRotate_WhenAccessTokenSigningFails()
    {
        var fixture = CreateFixture(signingFails: true);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => fixture.Manager.RefreshAsync("refresh-token"));

        Assert.Equal(0, fixture.RefreshTokens.RefreshCallCount);
    }

    [Fact]
    public async Task RefreshAsync_ShouldReturnNeitherToken_WhenConcurrentRotationLosesRace()
    {
        var fixture = CreateFixture();
        fixture.RefreshTokens.RenewalResult =
            RefreshTokenRenewalResult<Guid>.Failure(
                RefreshTokenErrorCodes.ConcurrencyConflict);

        var result = await fixture.Manager.RefreshAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Equal(TokenRefreshErrorCode.ConcurrencyConflict, result.ErrorCode);
        Assert.Null(result.AccessToken);
        Assert.Null(result.RefreshToken);
        Assert.Equal(1, fixture.SigningProvider.CallCount);
        Assert.Equal(1, fixture.RefreshTokens.RefreshCallCount);
    }

    [Fact]
    public async Task RefreshAsync_ShouldRejectOwnerMismatchAfterRotation()
    {
        var fixture = CreateFixture();
        fixture.RefreshTokens.RenewalResult =
            RefreshTokenRenewalResult<Guid>.Success(
                Guid.NewGuid(),
                "replacement-refresh-token");

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => fixture.Manager.RefreshAsync("refresh-token"));
    }

    [Fact]
    public async Task RefreshAsync_ShouldReturnPairForValidatedStoredOwner()
    {
        var fixture = CreateFixture();

        var result = await fixture.Manager.RefreshAsync("refresh-token");

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.AccessToken);
        Assert.Equal("replacement-refresh-token", result.RefreshToken);
        Assert.Null(result.ErrorCode);
        Assert.Equal(1, fixture.RefreshTokens.ValidateCallCount);
        Assert.Equal(1, fixture.RefreshTokens.RefreshCallCount);
    }

    private static TestFixture CreateFixture(
        bool userExists = true,
        bool lockedOut = false,
        bool canSignIn = true,
        bool twoFactorEnabled = false,
        bool signingFails = false)
    {
        var owner = Guid.NewGuid();
        var user = new TestUser
        {
            CanonicalId = owner.ToString(),
            LockoutEnd = lockedOut ? DateTimeOffset.UtcNow.AddMinutes(5) : null
        };
        var refreshTokens = new TestRefreshTokenManager(owner);
        var signInManager = new TestSignInManager(canSignIn, twoFactorEnabled);
        var signingProvider = new TestSigningCredentialsProvider(signingFails);
        var accessTokens = new AccessTokenManager(
            signingProvider,
            TimeProvider.System,
            Options.Create(new AccessTokenOptions
            {
                Issuer = "issuer",
                Audience = "audience"
            }));
        var manager = new TokenRefreshManager<TestUser, Guid>(
            refreshTokens,
            new TestRefreshTokenUserResolver(userExists ? user : null),
            new TestTokenUserIdentityResolver(
                new TokenUserIdentity<Guid>(owner, user.CanonicalId)),
            signInManager,
            accessTokens);

        return new TestFixture(manager, refreshTokens, signingProvider);
    }

    private sealed record TestFixture(
        TokenRefreshManager<TestUser, Guid> Manager,
        TestRefreshTokenManager RefreshTokens,
        TestSigningCredentialsProvider SigningProvider);

    private sealed class TestUser
    {
        public string CanonicalId { get; init; } = string.Empty;
        public DateTimeOffset? LockoutEnd { get; set; }
        public bool LockoutEnabled { get; set; } = true;
    }

    private sealed class TestRefreshTokenUserResolver
        : IRefreshTokenUserResolver<TestUser, Guid>
    {
        private readonly TestUser? _user;
        public TestRefreshTokenUserResolver(TestUser? user) => _user = user;
        public Task<TestUser?> ResolveAsync(Guid userId, CancellationToken cancellationToken = default) =>
            Task.FromResult(_user);
    }

    private sealed class TestTokenUserIdentityResolver
        : ITokenUserIdentityResolver<TestUser, Guid>
    {
        private readonly TokenUserIdentity<Guid> _identity;
        public TestTokenUserIdentityResolver(TokenUserIdentity<Guid> identity) => _identity = identity;
        public Task<TokenUserIdentity<Guid>> ResolveAsync(
            TestUser user,
            CancellationToken cancellationToken = default) => Task.FromResult(_identity);
    }

    private sealed class TestRefreshTokenManager : IRefreshTokenManager<Guid>
    {
        public TestRefreshTokenManager(Guid owner)
        {
            ValidationResult = RefreshTokenValidationResult<Guid>.Success(owner);
            RenewalResult = RefreshTokenRenewalResult<Guid>.Success(
                owner,
                "replacement-refresh-token");
        }

        public RefreshTokenValidationResult<Guid> ValidationResult { get; set; }
        public RefreshTokenRenewalResult<Guid> RenewalResult { get; set; }
        public int ValidateCallCount { get; private set; }
        public int RefreshCallCount { get; private set; }

        public Task<RefreshTokenValidationResult<Guid>> ValidateAsync(
            string refreshToken,
            CancellationToken cancellationToken = default)
        {
            ValidateCallCount++;
            return Task.FromResult(ValidationResult);
        }

        public Task<RefreshTokenRenewalResult<Guid>> RefreshAsync(
            string refreshToken,
            CancellationToken cancellationToken = default)
        {
            RefreshCallCount++;
            return Task.FromResult(RenewalResult);
        }

        public Task<RefreshTokenResult> CreateAsync(
            Guid userId,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class TestSigningCredentialsProvider
        : IAccessTokenSigningCredentialsProvider
    {
        private readonly bool _fails;
        public TestSigningCredentialsProvider(bool fails) => _fails = fails;
        public int CallCount { get; private set; }
        public SigningCredentials GetSigningCredentials()
        {
            CallCount++;
            if (_fails) throw new InvalidOperationException("Signing failed.");
            return new SigningCredentials(
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes("test-signing-key-material-long-enough-for-hs256")),
                SecurityAlgorithms.HmacSha256);
        }
    }

    private sealed class TestSignInManager : SignInManager<TestUser>
    {
        private readonly bool _canSignIn;
        private readonly bool _twoFactorEnabled;
        public TestSignInManager(bool canSignIn, bool twoFactorEnabled)
            : base(
                new TestUserManager(),
                new HttpContextAccessor(),
                new TestClaimsPrincipalFactory(),
                Microsoft.Extensions.Options.Options.Create(new IdentityOptions()),
                NullLogger<SignInManager<TestUser>>.Instance,
                new AuthenticationSchemeProvider(
                    Microsoft.Extensions.Options.Options.Create(new AuthenticationOptions())),
                new DefaultUserConfirmation<TestUser>())
        {
            _canSignIn = canSignIn;
            _twoFactorEnabled = twoFactorEnabled;
        }
        public override Task<bool> CanSignInAsync(TestUser user) => Task.FromResult(_canSignIn);
        public override Task<bool> IsTwoFactorEnabledAsync(TestUser user) =>
            Task.FromResult(_twoFactorEnabled);
    }

    private sealed class TestUserManager : UserManager<TestUser>
    {
        public TestUserManager()
            : base(
                new TestUserStore(),
                Microsoft.Extensions.Options.Options.Create(new IdentityOptions()),
                new PasswordHasher<TestUser>(),
                Array.Empty<IUserValidator<TestUser>>(),
                Array.Empty<IPasswordValidator<TestUser>>(),
                new UpperInvariantLookupNormalizer(),
                new IdentityErrorDescriber(),
                null!,
                NullLogger<UserManager<TestUser>>.Instance) { }
    }

    private sealed class TestUserStore : IUserStore<TestUser>, IUserLockoutStore<TestUser>
    {
        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TestUser user, CancellationToken cancellationToken) =>
            Task.FromResult(user.LockoutEnd);
        public Task SetLockoutEndDateAsync(TestUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        { user.LockoutEnd = lockoutEnd; return Task.CompletedTask; }
        public Task<int> IncrementAccessFailedCountAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult(0);
        public Task ResetAccessFailedCountAsync(TestUser user, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<int> GetAccessFailedCountAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult(0);
        public Task<bool> GetLockoutEnabledAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult(user.LockoutEnabled);
        public Task SetLockoutEnabledAsync(TestUser user, bool enabled, CancellationToken cancellationToken)
        { user.LockoutEnabled = enabled; return Task.CompletedTask; }
        public Task<string> GetUserIdAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult(user.CanonicalId);
        public Task<string?> GetUserNameAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult<string?>(null);
        public Task SetUserNameAsync(TestUser user, string? userName, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<string?> GetNormalizedUserNameAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult<string?>(null);
        public Task SetNormalizedUserNameAsync(TestUser user, string? normalizedName, CancellationToken cancellationToken) => Task.CompletedTask;
        public Task<IdentityResult> CreateAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult(IdentityResult.Success);
        public Task<IdentityResult> UpdateAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult(IdentityResult.Success);
        public Task<IdentityResult> DeleteAsync(TestUser user, CancellationToken cancellationToken) => Task.FromResult(IdentityResult.Success);
        public Task<TestUser?> FindByIdAsync(string userId, CancellationToken cancellationToken) => Task.FromResult<TestUser?>(null);
        public Task<TestUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken) => Task.FromResult<TestUser?>(null);
        public void Dispose() { }
    }

    private sealed class TestClaimsPrincipalFactory : IUserClaimsPrincipalFactory<TestUser>
    {
        public Task<ClaimsPrincipal> CreateAsync(TestUser user) =>
            Task.FromResult(new ClaimsPrincipal(new ClaimsIdentity()));
    }
}
