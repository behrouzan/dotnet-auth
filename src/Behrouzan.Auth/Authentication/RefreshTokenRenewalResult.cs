namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Represents the result of atomically rotating a refresh token.
/// </summary>
/// <typeparam name="TKey">The type of the user identifier.</typeparam>
public sealed class RefreshTokenRenewalResult<TKey>
    where TKey : notnull
{
    private RefreshTokenRenewalResult(TKey? userId, string? token, string? errorCode)
    {
        UserId = userId;
        Token = token;
        ErrorCode = errorCode;
    }

    /// <summary>Gets whether rotation succeeded.</summary>
    public bool IsSuccess => ErrorCode is null;

    /// <summary>Gets the owner obtained from the validated stored token on success.</summary>
    public TKey? UserId { get; }

    /// <summary>Gets the replacement raw refresh token on success.</summary>
    public string? Token { get; }

    /// <summary>Gets the existing refresh-token error code on failure.</summary>
    public string? ErrorCode { get; }

    /// <summary>Creates a successful renewal result.</summary>
    /// <param name="userId">The owner obtained from stored token data.</param>
    /// <param name="token">The replacement raw refresh token.</param>
    /// <returns>A successful renewal result.</returns>
    public static RefreshTokenRenewalResult<TKey> Success(TKey userId, string token)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        return new(userId, token, null);
    }

    /// <summary>Creates a failed renewal result.</summary>
    /// <param name="errorCode">The refresh-token error code.</param>
    /// <returns>A failed renewal result.</returns>
    public static RefreshTokenRenewalResult<TKey> Failure(string errorCode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(errorCode);
        return new(default, null, errorCode);
    }
}
