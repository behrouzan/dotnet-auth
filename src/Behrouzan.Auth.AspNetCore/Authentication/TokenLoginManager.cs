using Behrouzan.Auth.Authentication;
using Microsoft.AspNetCore.Identity;

namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Authenticates password credentials and issues an access-token and refresh-token pair.
/// </summary>
/// <typeparam name="TUser">The application user type.</typeparam>
/// <typeparam name="TKey">The type of the persisted user identifier.</typeparam>
public sealed class TokenLoginManager<TUser, TKey>
    where TUser : class
    where TKey : notnull
{
    private readonly PasswordAuthenticationManager<TUser> _passwordAuthenticationManager;
    private readonly SignInManager<TUser> _signInManager;
    private readonly ITokenUserIdentityResolver<TUser, TKey> _identityResolver;
    private readonly AccessTokenManager _accessTokenManager;
    private readonly IRefreshTokenManager<TKey> _refreshTokenManager;

    /// <summary>
    /// Initializes a new token-login manager.
    /// </summary>
    /// <param name="passwordAuthenticationManager">The reusable password authenticator.</param>
    /// <param name="signInManager">The ASP.NET Core Identity sign-in manager.</param>
    /// <param name="identityResolver">The resolver for the typed user ID and canonical subject.</param>
    /// <param name="accessTokenManager">The access-token issuer.</param>
    /// <param name="refreshTokenManager">The refresh-token manager.</param>
    public TokenLoginManager(
        PasswordAuthenticationManager<TUser> passwordAuthenticationManager,
        SignInManager<TUser> signInManager,
        ITokenUserIdentityResolver<TUser, TKey> identityResolver,
        AccessTokenManager accessTokenManager,
        IRefreshTokenManager<TKey> refreshTokenManager)
    {
        _passwordAuthenticationManager = passwordAuthenticationManager;
        _signInManager = signInManager;
        _identityResolver = identityResolver;
        _accessTokenManager = accessTokenManager;
        _refreshTokenManager = refreshTokenManager;
    }

    /// <summary>
    /// Authenticates an identifier and password and issues a token pair when all required
    /// authentication factors have been satisfied.
    /// </summary>
    /// <param name="identifier">The identifier used to locate the user.</param>
    /// <param name="password">The user's password.</param>
    /// <param name="cancellationToken">A token that can be used to cancel asynchronous work.</param>
    /// <returns>The issued token pair or the reason login did not complete.</returns>
    public async Task<TokenLoginResult> LoginAsync(
        string identifier,
        string password,
        CancellationToken cancellationToken = default)
    {
        var authentication = await _passwordAuthenticationManager.AuthenticateAsync(
            identifier,
            password,
            cancellationToken);

        if (!authentication.IsSuccess)
        {
            return TokenLoginResult.Failure(Map(authentication.ErrorCode));
        }

        var user = authentication.User!;

        if (await _signInManager.IsTwoFactorEnabledAsync(user))
        {
            return TokenLoginResult.Failure(TokenLoginErrorCode.RequiresTwoFactor);
        }

        var identity = await _identityResolver.ResolveAsync(user, cancellationToken);
        var canonicalSubject = await _signInManager.UserManager.GetUserIdAsync(user);

        if (identity is null ||
            identity.UserId is null ||
            string.IsNullOrWhiteSpace(identity.Subject) ||
            string.IsNullOrWhiteSpace(canonicalSubject) ||
            !string.Equals(identity.Subject, canonicalSubject, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The token user identity must contain a usable user ID and the canonical Identity user ID as its subject.");
        }

        var accessToken = _accessTokenManager.Create(identity.Subject);
        var refreshToken = await _refreshTokenManager.CreateAsync(
            identity.UserId,
            cancellationToken);

        if (!refreshToken.IsSuccess || string.IsNullOrWhiteSpace(refreshToken.Token))
        {
            return TokenLoginResult.Failure(
                TokenLoginErrorCode.RefreshTokenCreationFailed);
        }

        return TokenLoginResult.Success(accessToken, refreshToken.Token);
    }

    private static TokenLoginErrorCode Map(
        PasswordAuthenticationErrorCode? errorCode)
    {
        return errorCode switch
        {
            PasswordAuthenticationErrorCode.LockedOut => TokenLoginErrorCode.LockedOut,
            PasswordAuthenticationErrorCode.NotAllowed => TokenLoginErrorCode.NotAllowed,
            _ => TokenLoginErrorCode.InvalidCredentials
        };
    }
}
