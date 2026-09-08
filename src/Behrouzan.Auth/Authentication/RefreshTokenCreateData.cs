namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Represents the data required to persist a newly created refresh token.
/// </summary>
/// <typeparam name="TKey">The type of the user identifier.</typeparam>
public sealed class RefreshTokenCreateData<TKey>
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
    /// Gets the cryptographic hash of the refresh token.
    /// </summary>
    public required byte[] TokenHash { get; init; }

    /// <summary>
    /// Gets the time at which the refresh token was created.
    /// </summary>
    public required DateTimeOffset CreatedAt { get; init; }

    /// <summary>
    /// Gets the time at which the refresh token expires.
    /// </summary>
    public required DateTimeOffset ExpiresAt { get; init; }
}