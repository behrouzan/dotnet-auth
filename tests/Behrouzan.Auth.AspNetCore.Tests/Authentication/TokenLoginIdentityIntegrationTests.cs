using System.Text;
using Behrouzan.Auth.AspNetCore.Authentication;
using Behrouzan.Auth.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace Behrouzan.Auth.AspNetCore.Tests.Authentication;

public sealed class TokenLoginIdentityIntegrationTests
{
    [Fact]
    public async Task DefaultResolver_ShouldUseIdentityUserIdAndCanonicalUserManagerId()
    {
        await using var provider = CreateServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<TestUser>>();
        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            UserName = "behzad"
        };

        var createResult = await userManager.CreateAsync(user, "Correct-password1!");
        Assert.True(createResult.Succeeded);

        var resolver = new DefaultTokenUserIdentityResolver<TestUser, Guid>(userManager);
        var identity = await resolver.ResolveAsync(user);

        Assert.Equal(user.Id, identity.UserId);
        Assert.Equal(await userManager.GetUserIdAsync(user), identity.Subject);
    }

    [Fact]
    public async Task LoginAsync_ShouldRequireTwoFactorDespiteRememberedBrowser_WithoutApplicationCookie()
    {
        await using var provider = CreateServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var userManager = services.GetRequiredService<UserManager<TestUser>>();
        var signInManager = services.GetRequiredService<SignInManager<TestUser>>();
        var httpContextAccessor = services.GetRequiredService<IHttpContextAccessor>();
        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            UserName = "behzad"
        };

        var createResult = await userManager.CreateAsync(user, "Correct-password1!");
        Assert.True(createResult.Succeeded);
        var twoFactorResult = await userManager.SetTwoFactorEnabledAsync(user, true);
        Assert.True(twoFactorResult.Succeeded);
        Assert.True(await signInManager.IsTwoFactorEnabledAsync(user));

        var rememberContext = CreateHttpContext(services);
        httpContextAccessor.HttpContext = rememberContext;
        await signInManager.RememberTwoFactorClientAsync(user);
        var rememberedCookie = ToCookieHeader(rememberContext.Response.Headers.SetCookie);
        Assert.Contains(
            CookieAuthenticationDefaults.CookiePrefix + IdentityConstants.TwoFactorRememberMeScheme,
            rememberedCookie,
            StringComparison.Ordinal);

        await using var loginScope = provider.CreateAsyncScope();
        var loginServices = loginScope.ServiceProvider;
        var loginUserManager = loginServices.GetRequiredService<UserManager<TestUser>>();
        var loginSignInManager = loginServices.GetRequiredService<SignInManager<TestUser>>();
        var loginHttpContextAccessor = loginServices.GetRequiredService<IHttpContextAccessor>();
        var loginUser = await loginUserManager.FindByIdAsync(user.Id.ToString());
        Assert.NotNull(loginUser);
        var loginContext = CreateHttpContext(loginServices);
        loginContext.Request.Headers.Cookie = rememberedCookie;
        loginHttpContextAccessor.HttpContext = loginContext;
        Assert.True(await loginSignInManager.IsTwoFactorClientRememberedAsync(loginUser));

        var signingProvider = new CountingSigningCredentialsProvider();
        var refreshTokens = new CountingRefreshTokenManager();
        var passwordAuthenticationManager = new PasswordAuthenticationManager<TestUser>(
            new FixedUserSignInResolver(loginUser),
            loginSignInManager,
            Options.Create(new PasswordSignInOptions()));
        var accessTokenManager = new AccessTokenManager(
            signingProvider,
            TimeProvider.System,
            Options.Create(new AccessTokenOptions
            {
                Issuer = "issuer",
                Audience = "audience"
            }));
        var manager = new TokenLoginManager<TestUser, Guid>(
            passwordAuthenticationManager,
            loginSignInManager,
            new DefaultTokenUserIdentityResolver<TestUser, Guid>(loginUserManager),
            accessTokenManager,
            refreshTokens);

        var result = await manager.LoginAsync("behzad", "Correct-password1!");

        Assert.False(result.IsSuccess);
        Assert.Equal(TokenLoginErrorCode.RequiresTwoFactor, result.ErrorCode);
        Assert.Null(result.AccessToken);
        Assert.Null(result.RefreshToken);
        Assert.Equal(0, signingProvider.CallCount);
        Assert.Equal(0, refreshTokens.CreateCallCount);
        Assert.Empty(loginContext.Response.Headers.SetCookie);
    }

    private static ServiceProvider CreateServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection();
        services.AddSingleton<IDataProtectionProvider>(
            new EphemeralDataProtectionProvider());
        services.AddHttpContextAccessor();
        services
            .AddAuthentication()
            .AddCookie(IdentityConstants.ApplicationScheme)
            .AddCookie(IdentityConstants.TwoFactorRememberMeScheme)
            .AddCookie(IdentityConstants.TwoFactorUserIdScheme);
        services
            .AddIdentityCore<TestUser>()
            .AddSignInManager()
            .AddTokenProvider<AlwaysAvailableTwoFactorTokenProvider>("Test");
        services.AddSingleton<InMemoryUserStore>();
        services.AddSingleton<IUserStore<TestUser>>(
            serviceProvider => serviceProvider.GetRequiredService<InMemoryUserStore>());

        return services.BuildServiceProvider();
    }

    private static DefaultHttpContext CreateHttpContext(IServiceProvider services)
    {
        return new DefaultHttpContext
        {
            RequestServices = services
        };
    }

    private static string ToCookieHeader(StringValues setCookieHeaders)
    {
        return string.Join(
            "; ",
            setCookieHeaders
                .Select(header => header!.Split(';', 2)[0]));
    }

    private sealed class TestUser : IdentityUser<Guid>
    {
    }

    private sealed class FixedUserSignInResolver : IUserSignInResolver<TestUser>
    {
        private readonly TestUser _user;

        public FixedUserSignInResolver(TestUser user)
        {
            _user = user;
        }

        public Task<UserSignInResolution<TestUser>> ResolveAsync(
            string identifier,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(UserSignInResolution<TestUser>.Resolved(_user));
        }
    }

    private sealed class CountingSigningCredentialsProvider
        : IAccessTokenSigningCredentialsProvider
    {
        public int CallCount { get; private set; }

        public SigningCredentials GetSigningCredentials()
        {
            CallCount++;
            return new SigningCredentials(
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes("test-signing-key-material-long-enough-for-hs256")),
                SecurityAlgorithms.HmacSha256);
        }
    }

    private sealed class CountingRefreshTokenManager : IRefreshTokenManager<Guid>
    {
        public int CreateCallCount { get; private set; }

        public Task<RefreshTokenResult> CreateAsync(
            Guid userId,
            CancellationToken cancellationToken = default)
        {
            CreateCallCount++;
            return Task.FromResult(RefreshTokenResult.Success("refresh-token"));
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

    private sealed class AlwaysAvailableTwoFactorTokenProvider
        : IUserTwoFactorTokenProvider<TestUser>
    {
        public Task<bool> CanGenerateTwoFactorTokenAsync(
            UserManager<TestUser> manager,
            TestUser user) => Task.FromResult(true);

        public Task<string> GenerateAsync(
            string purpose,
            UserManager<TestUser> manager,
            TestUser user) => Task.FromResult("code");

        public Task<bool> ValidateAsync(
            string purpose,
            string token,
            UserManager<TestUser> manager,
            TestUser user) => Task.FromResult(token == "code");
    }

    private sealed class InMemoryUserStore :
        IUserStore<TestUser>,
        IUserPasswordStore<TestUser>,
        IUserTwoFactorStore<TestUser>,
        IUserSecurityStampStore<TestUser>
    {
        private readonly List<TestUser> _users = [];

        public Task<IdentityResult> CreateAsync(TestUser user, CancellationToken cancellationToken)
        {
            _users.Add(user);
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<IdentityResult> UpdateAsync(TestUser user, CancellationToken cancellationToken) =>
            Task.FromResult(IdentityResult.Success);

        public Task<IdentityResult> DeleteAsync(TestUser user, CancellationToken cancellationToken)
        {
            _users.Remove(user);
            return Task.FromResult(IdentityResult.Success);
        }

        public Task<TestUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            var id = Guid.Parse(userId);
            return Task.FromResult(_users.SingleOrDefault(user => user.Id == id));
        }

        public Task<TestUser?> FindByNameAsync(
            string normalizedUserName,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(
                _users.SingleOrDefault(user => user.NormalizedUserName == normalizedUserName));
        }

        public Task<string> GetUserIdAsync(TestUser user, CancellationToken cancellationToken) =>
            Task.FromResult(user.Id.ToString());

        public Task<string?> GetUserNameAsync(TestUser user, CancellationToken cancellationToken) =>
            Task.FromResult(user.UserName);

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
            CancellationToken cancellationToken) => Task.FromResult(user.NormalizedUserName);

        public Task SetNormalizedUserNameAsync(
            TestUser user,
            string? normalizedName,
            CancellationToken cancellationToken)
        {
            user.NormalizedUserName = normalizedName;
            return Task.CompletedTask;
        }

        public Task SetPasswordHashAsync(
            TestUser user,
            string? passwordHash,
            CancellationToken cancellationToken)
        {
            user.PasswordHash = passwordHash;
            return Task.CompletedTask;
        }

        public Task<string?> GetPasswordHashAsync(
            TestUser user,
            CancellationToken cancellationToken) => Task.FromResult(user.PasswordHash);

        public Task<bool> HasPasswordAsync(TestUser user, CancellationToken cancellationToken) =>
            Task.FromResult(user.PasswordHash is not null);

        public Task SetTwoFactorEnabledAsync(
            TestUser user,
            bool enabled,
            CancellationToken cancellationToken)
        {
            user.TwoFactorEnabled = enabled;
            return Task.CompletedTask;
        }

        public Task<bool> GetTwoFactorEnabledAsync(
            TestUser user,
            CancellationToken cancellationToken) => Task.FromResult(user.TwoFactorEnabled);

        public Task SetSecurityStampAsync(
            TestUser user,
            string stamp,
            CancellationToken cancellationToken)
        {
            user.SecurityStamp = stamp;
            return Task.CompletedTask;
        }

        public Task<string?> GetSecurityStampAsync(
            TestUser user,
            CancellationToken cancellationToken) => Task.FromResult(user.SecurityStamp);

        public void Dispose()
        {
        }
    }
}
