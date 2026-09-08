namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Provides error codes for refresh token operations.
/// </summary>
public static class RefreshTokenErrorCodes
{
    /// <summary>
    /// Indicates that the supplied refresh token is invalid or could not be found.
    /// </summary>
    public const string InvalidToken = "refresh_token_invalid";

    /// <summary>
    /// Indicates that the supplied refresh token has expired.
    /// </summary>
    public const string Expired = "refresh_token_expired";

    /// <summary>
    /// Indicates that the supplied refresh token has been revoked.
    /// </summary>
    public const string Revoked = "refresh_token_revoked";

    /// <summary>
    /// Indicates that a previously rotated refresh token has been reused.
    /// </summary>
    public const string ReuseDetected = "refresh_token_reuse_detected";

    /// <summary>
    /// Indicates that the refresh token could not be rotated because its state
    /// changed concurrently while the refresh operation was being processed.
    /// </summary>
    public const string ConcurrencyConflict = "refresh_token_concurrency_conflict";
}