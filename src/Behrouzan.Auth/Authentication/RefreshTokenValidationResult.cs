namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Represents the result of validating a refresh token without mutating it.
/// </summary>
/// <typeparam name="TKey">The type of the user identifier.</typeparam>
public sealed class RefreshTokenValidationResult<TKey>
    where TKey : notnull
{
    private RefreshTokenValidationResult(TKey? userId, string? errorCode)
    {
        UserId = userId;
        ErrorCode = errorCode;
    }

    /// <summary>Gets whether validation succeeded.</summary>
    public bool IsSuccess => ErrorCode is null;

    /// <summary>Gets the owner obtained from the validated stored token on success.</summary>
    public TKey? UserId { get; }

    /// <summary>Gets the existing refresh-token error code on failure.</summary>
    public string? ErrorCode { get; }

    /// <summary>Creates a successful validation result for the stored owner.</summary>
    /// <param name="userId">The owner obtained from stored token data.</param>
    /// <returns>A successful validation result.</returns>
    public static RefreshTokenValidationResult<TKey> Success(TKey userId)
    {
        ArgumentNullException.ThrowIfNull(userId);
        return new(userId, null);
    }

    /// <summary>Creates a failed validation result.</summary>
    /// <param name="errorCode">The refresh-token error code.</param>
    /// <returns>A failed validation result.</returns>
    public static RefreshTokenValidationResult<TKey> Failure(string errorCode)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(errorCode);
        return new(default, errorCode);
    }
}
