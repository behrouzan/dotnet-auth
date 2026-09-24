namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>Represents the result of refreshing an access-token and refresh-token pair.</summary>
public sealed class TokenRefreshResult
{
    private TokenRefreshResult(
        AccessToken? accessToken,
        string? refreshToken,
        TokenRefreshErrorCode? errorCode)
    {
        AccessToken = accessToken;
        RefreshToken = refreshToken;
        ErrorCode = errorCode;
    }

    /// <summary>Gets whether refresh succeeded.</summary>
    public bool IsSuccess => ErrorCode is null;
    /// <summary>Gets the new access token on success.</summary>
    public AccessToken? AccessToken { get; }
    /// <summary>Gets the rotated refresh token on success.</summary>
    public string? RefreshToken { get; }
    /// <summary>Gets the error code on failure.</summary>
    public TokenRefreshErrorCode? ErrorCode { get; }

    internal static TokenRefreshResult Success(AccessToken accessToken, string refreshToken) =>
        new(accessToken, refreshToken, null);

    internal static TokenRefreshResult Failure(TokenRefreshErrorCode errorCode) =>
        new(null, null, errorCode);
}
