using Behrouzan.Auth.Authentication;

namespace Behrouzan.Auth.EntityFrameworkCore.Authentication;
internal sealed class RefreshToken<TKey>
    where TKey : notnull
{
    public Guid TokenId { get; set; }

    public TKey UserId { get; set; } = default!;

    public byte[] TokenHash { get; set; } = default!;

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset? RevokedAt { get; set; }

    public RefreshTokenRevocationReason? RevocationReason { get; set; }

    public Guid? ReplacedByTokenId { get; set; }
}