using Microsoft.Extensions.Options;

namespace Behrouzan.Auth.Authentication;

internal sealed class RefreshTokenManager<TKey>
    : IRefreshTokenManager<TKey>
    where TKey : notnull
{
    private readonly IRefreshTokenStore<TKey> _store;
    private readonly RefreshTokenHasher _hasher;
    private readonly RefreshTokenGenerator _generator;
    private readonly TimeProvider _timeProvider;
    private readonly RefreshTokenOptions _options;

    public RefreshTokenManager(
        IRefreshTokenStore<TKey> store,
        RefreshTokenHasher hasher,
        RefreshTokenGenerator generator,
        TimeProvider timeProvider,
        IOptions<RefreshTokenOptions> options)
    {
        _store = store;
        _hasher = hasher;
        _generator = generator;
        _timeProvider = timeProvider;
        _options = options.Value;
    }

    public async Task<RefreshTokenResult> CreateAsync(TKey userId, CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        var (newRawToken, newTokenData) = CreateToken(userId, now);
        await _store.InsertAsync(newTokenData, cancellationToken);
        return RefreshTokenResult.Success(newRawToken);

    }

    public async Task<RefreshTokenResult> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return RefreshTokenResult.Failure(
                RefreshTokenErrorCodes.InvalidToken);
        }

        var now = _timeProvider.GetUtcNow();

        var hashedToken = _hasher.Hash(refreshToken);

        var tokenData = await _store.FindByHashAsync(
            hashedToken,
            cancellationToken);

        if (tokenData is null)
        {
            return RefreshTokenResult.Failure(
                RefreshTokenErrorCodes.InvalidToken);
        }

        if (tokenData.RevokedAt is not null &&
                tokenData.RevocationReason == RefreshTokenRevocationReason.Rotated &&
                tokenData.ReplacedByTokenId is not null)
        {
            return RefreshTokenResult.Failure(
                RefreshTokenErrorCodes.ReuseDetected);
        }

        if (tokenData.RevokedAt is not null)
        {
            return RefreshTokenResult.Failure(
                RefreshTokenErrorCodes.Revoked);
        }

        if (tokenData.ExpiresAt <= now)
        {
            return RefreshTokenResult.Failure(
                RefreshTokenErrorCodes.Expired);
        }

        var (newRawToken, newTokenData) =
            CreateToken(tokenData.UserId, now);

        var rotationData = new RefreshTokenRotationData
        {
            TokenId = tokenData.TokenId,
            RevokedAt = now,
            RevocationReason = RefreshTokenRevocationReason.Rotated,
        };

        var rotationResult = await _store.SaveRotationAsync(
            rotationData,
            newTokenData,
            cancellationToken);

        if (rotationResult.Succeeded)
        {
            return RefreshTokenResult.Success(newRawToken);
        }

        if (rotationResult.RevokedAt is not null &&
            rotationResult.RevocationReason == RefreshTokenRevocationReason.Rotated &&
            rotationResult.ReplacedByTokenId is not null)
        {
            return RefreshTokenResult.Failure(
                RefreshTokenErrorCodes.ReuseDetected);
        }

        if (rotationResult.RevokedAt is not null)
        {
            return RefreshTokenResult.Failure(
                RefreshTokenErrorCodes.Revoked);
        }

        return RefreshTokenResult.Failure(
            RefreshTokenErrorCodes.ConcurrencyConflict);
    }

    public async Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return;
        }

        var now = _timeProvider.GetUtcNow();

        var hashedToken = _hasher.Hash(refreshToken);

        var tokenData = await _store.FindByHashAsync(
            hashedToken,
            cancellationToken);

        if (tokenData is null ||
           tokenData.RevokedAt is not null ||
           tokenData.ExpiresAt <= now)
        {
            return;
        }

        var revocationData = new RefreshTokenRevocationData
        {
            TokenId = tokenData.TokenId,
            RevokedAt = now,
            RevocationReason = RefreshTokenRevocationReason.Logout
        };

        await _store.SaveRevocationAsync(revocationData, cancellationToken);

    }

    private (string RawToken, RefreshTokenCreateData<TKey> Data) CreateToken(
        TKey userId,
        DateTimeOffset now)
    {
        var rawToken = _generator.Generate();
        var hashedToken = _hasher.Hash(rawToken);
        var tokenId = Guid.NewGuid();

        var tokenData = new RefreshTokenCreateData<TKey>
        {
            TokenId = tokenId,
            UserId = userId,
            TokenHash = hashedToken,
            CreatedAt = now,
            ExpiresAt = now.Add(_options.Lifetime)
        };

        return (rawToken, tokenData);
    }
}