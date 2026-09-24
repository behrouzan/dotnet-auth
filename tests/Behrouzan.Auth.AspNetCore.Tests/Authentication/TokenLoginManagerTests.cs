using System.IdentityModel.Tokens.Jwt;
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

public sealed class TokenLoginManagerTests
{
    [Fact]
    public async Task LoginAsync_ShouldIssueTokenPairForCanonicalUserIdentity()
    {
        var userId = Guid.NewGuid();
        var user = new TestUser { CanonicalId = userId.ToString() };
        var signingProvider = new TestSigningCredentialsProvider();
        var refreshTokens = new TestRefreshTokenManager();
        var manager = CreateManager(
            user,
            SignInResult.Success,
            new TestTokenUserIdentityResolver(
                new TokenUserIdentity<Guid>(userId, user.CanonicalId)),
            signingProvider,
            refreshTokens);

        var result = await manager.LoginAsync("behzad", "password");

        Assert.True(result.IsSuccess);
        Assert.Equal("refresh-token", result.RefreshToken);
        Assert.NotNull(result.AccessToken);
        Assert.Null(result.ErrorCode);
        Assert.Equal(userId, refreshTokens.LastUserId);
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(result.AccessToken.Token);
        Assert.Equal(user.CanonicalId, jwt.Subject);
    }

    [Theory]
    [InlineData("failed", TokenLoginErrorCode.InvalidCredentials)]
    [InlineData("lockedOut", TokenLoginErrorCode.LockedOut)]
    [InlineData("notAllowed", TokenLoginErrorCode.NotAllowed)]
    public async Task LoginAsync_ShouldMapPasswordAuthenticationFailure(
        string identityResult,
        TokenLoginErrorCode expectedError)
    {
        var signInResult = identityResult switch
        {
            "lockedOut" => SignInResult.LockedOut,
            "notAllowed" => SignInResult.NotAllowed,
            _ => SignInResult.Failed
        };
        var signingProvider = new TestSigningCredentialsProvider();
        var refreshTokens = new TestRefreshTokenManager();
        var resolver = new TestTokenUserIdentityResolver(
            new TokenUserIdentity<Guid>(Guid.NewGuid(), "user-id"));
        var manager = CreateManager(
            new TestUser { CanonicalId = "user-id" },
            signInResult,
            resolver,
            signingProvider,
            refreshTokens);

        var result = await manager.LoginAsync("behzad", "password");

        Assert.False(result.IsSuccess);
        Assert.Equal(expectedError, result.ErrorCode);
        Assert.Null(result.AccessToken);
        Assert.Null(result.RefreshToken);
        Assert.Equal(0, resolver.CallCount);
        Assert.Equal(0, signingProvider.CallCount);
        Assert.Equal(0, refreshTokens.CreateCallCount);
    }

    [Theory]
    [InlineData(UserSignInResolutionStatus.NotFound)]
    [InlineData(UserSignInResolutionStatus.Ambiguous)]
    public async Task LoginAsync_ShouldReturnInvalidCredentials_WhenUserIsNotUniquelyResolved(
        UserSignInResolutionStatus status)
    {
        var resolution = status == UserSignInResolutionStatus.NotFound
            ? UserSignInResolution<TestUser>.NotFound()
            : UserSignInResolution<TestUser>.Ambiguous();
        var signingProvider = new TestSigningCredentialsProvider();
        var refreshTokens = new TestRefreshTokenManager();
        var identityResolver = new TestTokenUserIdentityResolver(
            new TokenUserIdentity<Guid>(Guid.NewGuid(), "user-id"));
        var manager = CreateManager(
            new TestUser { CanonicalId = "user-id" },
            SignInResult.Success,
            identityResolver,
            signingProvider,
            refreshTokens,
            userSignInResolver: new TestUserSignInResolver(resolution));

        var result = await manager.LoginAsync("identifier", "password");

        Assert.False(result.IsSuccess);
        Assert.Equal(TokenLoginErrorCode.InvalidCredentials, result.ErrorCode);
        Assert.Null(result.AccessToken);
        Assert.Null(result.RefreshToken);
        Assert.Equal(0, identityResolver.CallCount);
        Assert.Equal(0, signingProvider.CallCount);
        Assert.Equal(0, refreshTokens.CreateCallCount);
    }

    [Fact]
    public async Task LoginAsync_ShouldReturnRequiresTwoFactorWithoutIssuingTokens()
    {
        var signingProvider = new TestSigningCredentialsProvider();
        var refreshTokens = new TestRefreshTokenManager();
        var resolver = new TestTokenUserIdentityResolver(
            new TokenUserIdentity<Guid>(Guid.NewGuid(), "user-id"));
        var manager = CreateManager(
            new TestUser { CanonicalId = "user-id" },
            SignInResult.Success,
            resolver,
            signingProvider,
            refreshTokens,
            twoFactorEnabled: true);

        var result = await manager.LoginAsync("behzad", "password");

        Assert.False(result.IsSuccess);
        Assert.Equal(TokenLoginErrorCode.RequiresTwoFactor, result.ErrorCode);
        Assert.Null(result.AccessToken);
        Assert.Null(result.RefreshToken);
        Assert.Equal(0, resolver.CallCount);
        Assert.Equal(0, signingProvider.CallCount);
        Assert.Equal(0, refreshTokens.CreateCallCount);
    }

    [Fact]
    public async Task LoginAsync_ShouldNotPersistRefreshToken_WhenAccessTokenSigningFails()
    {
        var refreshTokens = new TestRefreshTokenManager();
        var manager = CreateManager(
            new TestUser { CanonicalId = "user-id" },
            SignInResult.Success,
            new TestTokenUserIdentityResolver(
                new TokenUserIdentity<Guid>(Guid.NewGuid(), "user-id")),
            new TestSigningCredentialsProvider(throwOnGet: true),
            refreshTokens);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => manager.LoginAsync("behzad", "password"));

        Assert.Equal(0, refreshTokens.CreateCallCount);
    }

    [Fact]
    public async Task LoginAsync_ShouldNotReturnAccessToken_WhenRefreshTokenCreationFails()
    {
        var signingProvider = new TestSigningCredentialsProvider();
        var refreshTokens = new TestRefreshTokenManager(
            RefreshTokenResult.Failure("store-failure"));
        var manager = CreateManager(
            new TestUser { CanonicalId = "user-id" },
            SignInResult.Success,
            new TestTokenUserIdentityResolver(
                new TokenUserIdentity<Guid>(Guid.NewGuid(), "user-id")),
            signingProvider,
            refreshTokens);

        var result = await manager.LoginAsync("behzad", "password");

        Assert.False(result.IsSuccess);
        Assert.Equal(TokenLoginErrorCode.RefreshTokenCreationFailed, result.ErrorCode);
        Assert.Null(result.AccessToken);
        Assert.Null(result.RefreshToken);
        Assert.Equal(1, signingProvider.CallCount);
        Assert.Equal(1, refreshTokens.CreateCallCount);
    }

    [Fact]
    public async Task LoginAsync_ShouldRejectSubjectThatDoesNotMatchCanonicalIdentityUserId()
    {
        var signingProvider = new TestSigningCredentialsProvider();
        var refreshTokens = new TestRefreshTokenManager();
        var manager = CreateManager(
            new TestUser { CanonicalId = "canonical-user-id" },
            SignInResult.Success,
            new TestTokenUserIdentityResolver(
                new TokenUserIdentity<Guid>(Guid.NewGuid(), "different-user-id")),
            signingProvider,
            refreshTokens);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => manager.LoginAsync("behzad", "password"));

        Assert.Equal(0, signingProvider.CallCount);
        Assert.Equal(0, refreshTokens.CreateCallCount);
    }

    private static TokenLoginManager<TestUser, Guid> CreateManager(
        TestUser user,
        SignInResult passwordResult,
        ITokenUserIdentityResolver<TestUser, Guid> identityResolver,
        TestSigningCredentialsProvider signingProvider,
        TestRefreshTokenManager refreshTokenManager,
        bool twoFactorEnabled = false,
        IUserSignInResolver<TestUser>? userSignInResolver = null)
    {
        var signInManager = new TestSignInManager(passwordResult, twoFactorEnabled);
        var passwordAuthenticationManager = new PasswordAuthenticationManager<TestUser>(
            userSignInResolver ?? new TestUserSignInResolver(user),
            signInManager,
            Options.Create(new PasswordSignInOptions()));
        var accessTokenManager = new AccessTokenManager(
            signingProvider,
            TimeProvider.System,
            Options.Create(new AccessTokenOptions
            {
                Issuer = "issuer",
                Audience = "audience"
            }));

        return new TokenLoginManager<TestUser, Guid>(
            passwordAuthenticationManager,
            signInManager,
            identityResolver,
            accessTokenManager,
            refreshTokenManager);
    }

    private sealed class TestUser
    {
        public string CanonicalId { get; init; } = string.Empty;
    }

    private sealed class TestUserSignInResolver : IUserSignInResolver<TestUser>
    {
        private readonly UserSignInResolution<TestUser> _resolution;

        public TestUserSignInResolver(TestUser user)
            : this(UserSignInResolution<TestUser>.Resolved(user))
        {
        }

        public TestUserSignInResolver(UserSignInResolution<TestUser> resolution)
        {
            _resolution = resolution;
        }

        public Task<UserSignInResolution<TestUser>> ResolveAsync(
            string identifier,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_resolution);
        }
    }

    private sealed class TestTokenUserIdentityResolver
        : ITokenUserIdentityResolver<TestUser, Guid>
    {
        private readonly TokenUserIdentity<Guid> _identity;

        public TestTokenUserIdentityResolver(TokenUserIdentity<Guid> identity)
        {
            _identity = identity;
        }

        public int CallCount { get; private set; }

        public Task<TokenUserIdentity<Guid>> ResolveAsync(
            TestUser user,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            return Task.FromResult(_identity);
        }
    }

    private sealed class TestRefreshTokenManager : IRefreshTokenManager<Guid>
    {
        private readonly RefreshTokenResult _result;

        public TestRefreshTokenManager(RefreshTokenResult? result = null)
        {
            _result = result ?? RefreshTokenResult.Success("refresh-token");
        }

        public int CreateCallCount { get; private set; }
        public Guid? LastUserId { get; private set; }

        public Task<RefreshTokenResult> CreateAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {
            CreateCallCount++;
            LastUserId = userId;
            return Task.FromResult(_result);
        }

        public Task<RefreshTokenRenewalResult<Guid>> RefreshAsync(
            string refreshToken,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<RefreshTokenValidationResult<Guid>> ValidateAsync(
            string refreshToken,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task RevokeAsync(
            string refreshToken,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();
    }

    private sealed class TestSigningCredentialsProvider
        : IAccessTokenSigningCredentialsProvider
    {
        private readonly bool _throwOnGet;

        public TestSigningCredentialsProvider(bool throwOnGet = false)
        {
            _throwOnGet = throwOnGet;
        }

        public int CallCount { get; private set; }

        public SigningCredentials GetSigningCredentials()
        {
            CallCount++;

            if (_throwOnGet)
            {
                throw new InvalidOperationException("Signing failed.");
            }

            return new SigningCredentials(
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes("test-signing-key-material-long-enough-for-hs256")),
                SecurityAlgorithms.HmacSha256);
        }
    }

    private sealed class TestSignInManager : SignInManager<TestUser>
    {
        private readonly SignInResult _passwordResult;
        private readonly bool _twoFactorEnabled;

        public TestSignInManager(SignInResult passwordResult, bool twoFactorEnabled)
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
            _passwordResult = passwordResult;
            _twoFactorEnabled = twoFactorEnabled;
        }

        public override Task<SignInResult> CheckPasswordSignInAsync(
            TestUser user,
            string password,
            bool lockoutOnFailure) => Task.FromResult(_passwordResult);

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
                NullLogger<UserManager<TestUser>>.Instance)
        {
        }
    }

    private sealed class TestUserStore : IUserStore<TestUser>
    {
        public void Dispose() { }

        public Task<string> GetUserIdAsync(TestUser user, CancellationToken cancellationToken) =>
            Task.FromResult(user.CanonicalId);

        public Task<string?> GetUserNameAsync(TestUser user, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task SetUserNameAsync(TestUser user, string? userName, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<string?> GetNormalizedUserNameAsync(TestUser user, CancellationToken cancellationToken) =>
            Task.FromResult<string?>(null);

        public Task SetNormalizedUserNameAsync(TestUser user, string? normalizedName, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<IdentityResult> CreateAsync(TestUser user, CancellationToken cancellationToken) =>
            Task.FromResult(IdentityResult.Success);

        public Task<IdentityResult> UpdateAsync(TestUser user, CancellationToken cancellationToken) =>
            Task.FromResult(IdentityResult.Success);

        public Task<IdentityResult> DeleteAsync(TestUser user, CancellationToken cancellationToken) =>
            Task.FromResult(IdentityResult.Success);

        public Task<TestUser?> FindByIdAsync(string userId, CancellationToken cancellationToken) =>
            Task.FromResult<TestUser?>(null);

        public Task<TestUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken) =>
            Task.FromResult<TestUser?>(null);
    }

    private sealed class TestClaimsPrincipalFactory : IUserClaimsPrincipalFactory<TestUser>
    {
        public Task<ClaimsPrincipal> CreateAsync(TestUser user) =>
            Task.FromResult(new ClaimsPrincipal(new ClaimsIdentity()));
    }
}
