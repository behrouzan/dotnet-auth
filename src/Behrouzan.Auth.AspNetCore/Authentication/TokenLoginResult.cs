namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Represents the result of a token-login attempt.
/// </summary>
public sealed class TokenLoginResult
{
    private TokenLoginResult(
        AccessToken? accessToken,
        string? refreshToken,
        TokenLoginErrorCode? errorCode)
    {
        AccessToken = accessToken;
        RefreshToken = refreshToken;
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Gets a value indicating whether token login succeeded.
    /// </summary>
    public bool IsSuccess => ErrorCode is null;

    /// <summary>
    /// Gets the access token when token login succeeds.
    /// </summary>
    public AccessToken? AccessToken { get; }

    /// <summary>
    /// Gets the refresh token when token login succeeds.
    /// </summary>
    public string? RefreshToken { get; }

    /// <summary>
    /// Gets the error code when token login fails.
    /// </summary>
    public TokenLoginErrorCode? ErrorCode { get; }

    internal static TokenLoginResult Success(
        AccessToken accessToken,
        string refreshToken)
    {
        return new(accessToken, refreshToken, null);
    }

    internal static TokenLoginResult Failure(TokenLoginErrorCode errorCode)
    {
        return new(null, null, errorCode);
    }
}
