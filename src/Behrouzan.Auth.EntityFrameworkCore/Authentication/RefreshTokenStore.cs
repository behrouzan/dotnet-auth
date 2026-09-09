using Behrouzan.Auth.Authentication;
using Microsoft.EntityFrameworkCore;

namespace Behrouzan.Auth.EntityFrameworkCore.Authentication;

internal sealed class RefreshTokenStore<TContext, TKey> : IRefreshTokenStore<TKey>
    where TContext : DbContext
    where TKey : notnull
{
    private readonly TContext _dbContext;

    public RefreshTokenStore(TContext dbContext)
    {
        ArgumentNullException.ThrowIfNull(dbContext);
        _dbContext = dbContext;
    }

    public async Task<RefreshTokenData<TKey>?> FindByHashAsync(byte[] tokenHash, CancellationToken cancellationToken = default)
    {
        return await _dbContext.Set<RefreshToken<TKey>>()
        .Where(x => x.TokenHash.SequenceEqual(tokenHash))
        .Select(d => new RefreshTokenData<TKey>()
        {
            TokenId = d.TokenId,
            UserId = d.UserId,
            ExpiresAt = d.ExpiresAt,
            RevokedAt = d.RevokedAt,
            RevocationReason = d.RevocationReason,
            ReplacedByTokenId = d.ReplacedByTokenId
        }).FirstOrDefaultAsync(cancellationToken);
    }

    public async Task InsertAsync(RefreshTokenCreateData<TKey> refreshToken,
        CancellationToken cancellationToken = default)
    {
        RefreshToken<TKey> token = new RefreshToken<TKey>()
        {
            TokenId = refreshToken.TokenId,
            UserId = refreshToken.UserId,
            TokenHash = refreshToken.TokenHash,
            CreatedAt = refreshToken.CreatedAt,
            ExpiresAt = refreshToken.ExpiresAt
        };
        await _dbContext.Set<RefreshToken<TKey>>().AddAsync(token, cancellationToken);
        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task SaveRevocationAsync(RefreshTokenRevocationData refreshToken,
        CancellationToken cancellationToken = default)
    {
        await _dbContext
            .Set<RefreshToken<TKey>>()
            .Where(c => c.TokenId == refreshToken.TokenId && c.RevokedAt == null)
            .ExecuteUpdateAsync(
                setters => setters
                    .SetProperty(c => c.RevokedAt, refreshToken.RevokedAt)
                    .SetProperty(c => c.RevocationReason, refreshToken.RevocationReason),
                cancellationToken);
    }

    public async Task<RefreshTokenRotationResult> SaveRotationAsync(
      RefreshTokenRotationData currentToken,
      RefreshTokenCreateData<TKey> newToken,
      CancellationToken cancellationToken = default)
    {
        var newTokenEntity = new RefreshToken<TKey>
        {
            TokenId = newToken.TokenId,
            UserId = newToken.UserId,
            TokenHash = newToken.TokenHash,
            CreatedAt = newToken.CreatedAt,
            ExpiresAt = newToken.ExpiresAt
        };

        await using var transaction =
            await _dbContext.Database.BeginTransactionAsync(
                cancellationToken);

        try
        {


            await _dbContext
                .Set<RefreshToken<TKey>>()
                .AddAsync(
                    newTokenEntity,
                    cancellationToken);

            await _dbContext.SaveChangesAsync(
                cancellationToken);

            var affectedRows = await _dbContext
                .Set<RefreshToken<TKey>>()
                .Where(token =>
                    token.TokenId == currentToken.TokenId &&
                    token.RevokedAt == null)
                .ExecuteUpdateAsync(
                    setters => setters
                        .SetProperty(
                            token => token.RevokedAt,
                            currentToken.RevokedAt)
                        .SetProperty(
                            token => token.RevocationReason,
                            currentToken.RevocationReason)
                        .SetProperty(
                            token => token.ReplacedByTokenId,
                            currentToken.ReplacedByTokenId),
                    cancellationToken);

            if (affectedRows == 1)
            {
                await transaction.CommitAsync(
                    cancellationToken);

                return new RefreshTokenRotationResult
                {
                    Succeeded = true
                };
            }

            await transaction.RollbackAsync(
                cancellationToken);
            _dbContext.Entry(newTokenEntity).State = EntityState.Detached;

            var existingToken = await _dbContext
                .Set<RefreshToken<TKey>>()
                .AsNoTracking()
                .Where(token =>
                    token.TokenId == currentToken.TokenId)
                .Select(token => new
                {
                    token.RevokedAt,
                    token.RevocationReason,
                    token.ReplacedByTokenId
                })
                .FirstOrDefaultAsync(cancellationToken);

            return new RefreshTokenRotationResult
            {
                Succeeded = false,
                RevokedAt = existingToken?.RevokedAt,
                RevocationReason = existingToken?.RevocationReason,
                ReplacedByTokenId = existingToken?.ReplacedByTokenId
            };
        }
        catch
        {
            await transaction.RollbackAsync(
                cancellationToken);

            _dbContext.Entry(newTokenEntity).State =
                    EntityState.Detached;

            throw;
        }
    }

}