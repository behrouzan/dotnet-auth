using Behrouzan.Auth.Authentication;
using Microsoft.AspNetCore.Identity;

namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Validates and atomically rotates refresh tokens and issues replacement access tokens.
/// </summary>
/// <typeparam name="TUser">The application user type.</typeparam>
/// <typeparam name="TKey">The type of the persisted user identifier.</typeparam>
/// <remarks>
/// Security-stamp changes do not invalidate existing refresh tokens. The token feature must
/// define user-wide revocation or issuance-time security-stamp binding before release; the
/// current raw-token revocation API must not be treated as sign-out-everywhere behavior.
/// </remarks>
public sealed class TokenRefreshManager<TUser, TKey>
    where TUser : class
    where TKey : notnull
{
    private readonly IRefreshTokenManager<TKey> _refreshTokenManager;
    private readonly IRefreshTokenUserResolver<TUser, TKey> _userResolver;
    private readonly ITokenUserIdentityResolver<TUser, TKey> _identityResolver;
    private readonly SignInManager<TUser> _signInManager;
    private readonly AccessTokenManager _accessTokenManager;

    /// <summary>Initializes a new token-refresh manager.</summary>
    /// <param name="refreshTokenManager">The refresh-token validator and rotation manager.</param>
    /// <param name="userResolver">The resolver for a stored owner to its current user.</param>
    /// <param name="identityResolver">The resolver for the user's typed ID and canonical subject.</param>
    /// <param name="signInManager">The ASP.NET Core Identity sign-in manager.</param>
    /// <param name="accessTokenManager">The access-token issuer.</param>
    public TokenRefreshManager(
        IRefreshTokenManager<TKey> refreshTokenManager,
        IRefreshTokenUserResolver<TUser, TKey> userResolver,
        ITokenUserIdentityResolver<TUser, TKey> identityResolver,
        SignInManager<TUser> signInManager,
        AccessTokenManager accessTokenManager)
    {
        _refreshTokenManager = refreshTokenManager;
        _userResolver = userResolver;
        _identityResolver = identityResolver;
        _signInManager = signInManager;
        _accessTokenManager = accessTokenManager;
    }

    /// <summary>Refreshes a token pair using an existing refresh token.</summary>
    /// <param name="refreshToken">The existing raw refresh token.</param>
    /// <param name="cancellationToken">A token used to cancel asynchronous work.</param>
    /// <returns>The replacement token pair or the reason refresh failed.</returns>
    public async Task<TokenRefreshResult> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken = default)
    {
        var validation = await _refreshTokenManager.ValidateAsync(
            refreshToken,
            cancellationToken);

        if (!validation.IsSuccess || validation.UserId is null)
        {
            return TokenRefreshResult.Failure(Map(validation.ErrorCode));
        }

        var validatedOwner = validation.UserId;
        var user = await _userResolver.ResolveAsync(validatedOwner, cancellationToken);

        if (user is null)
        {
            return TokenRefreshResult.Failure(TokenRefreshErrorCode.InvalidToken);
        }

        var userManager = _signInManager.UserManager;

        if (userManager.SupportsUserLockout && await userManager.IsLockedOutAsync(user))
        {
            return TokenRefreshResult.Failure(TokenRefreshErrorCode.LockedOut);
        }

        if (!await _signInManager.CanSignInAsync(user))
        {
            return TokenRefreshResult.Failure(TokenRefreshErrorCode.NotAllowed);
        }

        if (await _signInManager.IsTwoFactorEnabledAsync(user))
        {
            return TokenRefreshResult.Failure(TokenRefreshErrorCode.RequiresTwoFactor);
        }

        var identity = await _identityResolver.ResolveAsync(user, cancellationToken);
        var canonicalSubject = await userManager.GetUserIdAsync(user);

        if (identity is null ||
            identity.UserId is null ||
            !EqualityComparer<TKey>.Default.Equals(identity.UserId, validatedOwner) ||
            string.IsNullOrWhiteSpace(identity.Subject) ||
            string.IsNullOrWhiteSpace(canonicalSubject) ||
            !string.Equals(identity.Subject, canonicalSubject, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "The resolved token identity must match the validated refresh-token owner and canonical Identity user ID.");
        }

        var accessToken = _accessTokenManager.Create(identity.Subject);
        var renewal = await _refreshTokenManager.RefreshAsync(
            refreshToken,
            cancellationToken);

        if (!renewal.IsSuccess || renewal.UserId is null ||
            string.IsNullOrWhiteSpace(renewal.Token))
        {
            return TokenRefreshResult.Failure(Map(renewal.ErrorCode));
        }

        if (!EqualityComparer<TKey>.Default.Equals(renewal.UserId, validatedOwner))
        {
            throw new InvalidOperationException(
                "The rotated refresh-token owner does not match the validated owner.");
        }

        return TokenRefreshResult.Success(accessToken, renewal.Token);
    }

    private static TokenRefreshErrorCode Map(string? errorCode)
    {
        return errorCode switch
        {
            RefreshTokenErrorCodes.Expired => TokenRefreshErrorCode.Expired,
            RefreshTokenErrorCodes.Revoked => TokenRefreshErrorCode.Revoked,
            RefreshTokenErrorCodes.ReuseDetected => TokenRefreshErrorCode.ReuseDetected,
            RefreshTokenErrorCodes.ConcurrencyConflict => TokenRefreshErrorCode.ConcurrencyConflict,
            _ => TokenRefreshErrorCode.InvalidToken
        };
    }
}
