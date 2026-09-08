namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Represents the data required to persist a refresh token revocation.
/// </summary>
public class RefreshTokenRevocationData
{
    /// <summary>
    /// Gets the unique identifier of the refresh token.
    /// </summary>
    public required Guid TokenId { get; init; }

    /// <summary>
    /// Gets the time at which the refresh token was revoked.
    /// </summary>
    public required DateTimeOffset RevokedAt { get; init; }

    /// <summary>
    /// Gets the reason the refresh token was revoked.
    /// </summary>
    public required RefreshTokenRevocationReason RevocationReason { get; init; }
}

/// <summary>
/// Represents the data required to persist a refresh token rotation.
/// </summary>
public sealed class RefreshTokenRotationData
    : RefreshTokenRevocationData
{
    /// <summary>
    /// Gets the identifier of the refresh token that replaced the current token.
    /// </summary>
    public required Guid ReplacedByTokenId { get; init; }
}