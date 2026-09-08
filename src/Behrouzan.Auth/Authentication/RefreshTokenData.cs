namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Represents refresh token data exposed through the refresh token persistence contract.
/// </summary>
/// <typeparam name="TKey">The type of the user identifier.</typeparam>
public sealed class RefreshTokenData<TKey>
    where TKey : notnull
{
    /// <summary>
    /// Gets the unique identifier of the refresh token.
    /// </summary>
    public required Guid TokenId { get; init; }

    /// <summary>
    /// Gets the identifier of the user that owns the refresh token.
    /// </summary>
    public required TKey UserId { get; init; }

    /// <summary>
    /// Gets the time at which the refresh token expires.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }

    /// <summary>
    /// Gets the time at which the refresh token was revoked, if it has been revoked.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; init; }

    /// <summary>
    /// Gets the reason the refresh token was revoked, if it has been revoked.
    /// </summary>
    public RefreshTokenRevocationReason? RevocationReason { get; init; }

    /// <summary>
    /// Gets the identifier of the refresh token that replaced this token during rotation, if any.
    /// </summary>
    public Guid? ReplacedByTokenId { get; init; }
}