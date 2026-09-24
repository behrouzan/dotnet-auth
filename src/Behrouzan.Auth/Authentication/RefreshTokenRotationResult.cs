namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Represents the result of attempting to persist a refresh token rotation.
/// </summary>
public sealed class RefreshTokenRotationResult
{
    /// <summary>
    /// Gets a value indicating whether the rotation was persisted successfully.
    /// </summary>
    public required bool Succeeded { get; init; }

    /// <summary>
    /// Gets the time at which the current token had already been revoked
    /// when the rotation could not be performed.
    /// </summary>
    public DateTimeOffset? RevokedAt { get; init; }

    /// <summary>
    /// Gets the reason the current token had already been revoked
    /// when the rotation could not be performed.
    /// </summary>
    public RefreshTokenRevocationReason? RevocationReason { get; init; }

    /// <summary>
    /// Gets the identifier of the token that previously replaced the current
    /// token, if it had already been rotated.
    /// </summary>
    public Guid? ReplacedByTokenId { get; init; }

    /// <summary>
    /// Gets the expiration time observed when the rotation could not be performed.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }
}
