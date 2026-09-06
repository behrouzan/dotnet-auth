
internal class RefreshToken<TKey> where TKey : notnull
{
    public RefreshToken(Guid tokenId, TKey userId, byte[] tokenHash, DateTimeOffset createdAt, DateTimeOffset expiresAt)
    {
        TokenId = tokenId;
        UserId = userId;
        TokenHash = tokenHash.ToArray();
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }
    public Guid TokenId { get; private set; }
    public TKey UserId { get; private set; }
    public byte[] TokenHash { get; private set; }
    public DateTimeOffset CreatedAt { get; private set; }
    public DateTimeOffset ExpiresAt { get; private set; }
    public DateTimeOffset? RevokedAt { get; private set; }
    public RefreshTokenRevocationReason? RevocationReason { get; private set; }
    public Guid? ReplacedByTokenId { get; private set; }

    internal bool Revoke(
        DateTimeOffset revokedAt,
        RefreshTokenRevocationReason reason)
    {
        if (RevokedAt is not null)
            return false;

        RevokedAt = revokedAt;
        RevocationReason = reason;

        return true;
    }

    internal bool Rotate(DateTimeOffset revokedAt, Guid newTokenId)
    {
        if (RevokedAt is not null || ReplacedByTokenId is not null)
            return false;

        RevokedAt = revokedAt;
        ReplacedByTokenId = newTokenId;
        RevocationReason = RefreshTokenRevocationReason.Rotated;
        return true;
    }

    internal bool IsActive(DateTimeOffset now)
    {
        return RevokedAt is null && ExpiresAt > now;
    }
}

