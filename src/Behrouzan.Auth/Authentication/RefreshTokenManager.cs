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

    public async Task<RefreshTokenValidationResult<TKey>> ValidateAsync(
        string refreshToken,
        CancellationToken cancellationToken = default)
    {
        var validation = await ValidateTokenAsync(refreshToken, cancellationToken);

        return validation.Token is not null
            ? RefreshTokenValidationResult<TKey>.Success(validation.Token.UserId)
            : RefreshTokenValidationResult<TKey>.Failure(validation.ErrorCode!);
    }

    public async Task<RefreshTokenRenewalResult<TKey>> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken = default)
    {
        var validation = await ValidateTokenAsync(refreshToken, cancellationToken);

        if (validation.Token is null)
        {
            return RefreshTokenRenewalResult<TKey>.Failure(validation.ErrorCode!);
        }

        var now = _timeProvider.GetUtcNow();
        var tokenData = validation.Token;

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
            return RefreshTokenRenewalResult<TKey>.Success(tokenData.UserId, newRawToken);
        }

        if (rotationResult.RevokedAt is not null &&
            rotationResult.RevocationReason == RefreshTokenRevocationReason.Rotated &&
            rotationResult.ReplacedByTokenId is not null)
        {
            return RefreshTokenRenewalResult<TKey>.Failure(
                RefreshTokenErrorCodes.ReuseDetected);
        }

        if (rotationResult.RevokedAt is not null)
        {
            return RefreshTokenRenewalResult<TKey>.Failure(
                RefreshTokenErrorCodes.Revoked);
        }

        if (rotationResult.ExpiresAt <= now)
        {
            return RefreshTokenRenewalResult<TKey>.Failure(
                RefreshTokenErrorCodes.Expired);
        }

        return RefreshTokenRenewalResult<TKey>.Failure(
            RefreshTokenErrorCodes.ConcurrencyConflict);
    }

    private async Task<(RefreshTokenData<TKey>? Token, string? ErrorCode)> ValidateTokenAsync(
        string refreshToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return (null, RefreshTokenErrorCodes.InvalidToken);
        }

        var tokenData = await _store.FindByHashAsync(
            _hasher.Hash(refreshToken),
            cancellationToken);

        if (tokenData is null)
        {
            return (null, RefreshTokenErrorCodes.InvalidToken);
        }

        if (tokenData.RevokedAt is not null &&
            tokenData.RevocationReason == RefreshTokenRevocationReason.Rotated &&
            tokenData.ReplacedByTokenId is not null)
        {
            return (null, RefreshTokenErrorCodes.ReuseDetected);
        }

        if (tokenData.RevokedAt is not null)
        {
            return (null, RefreshTokenErrorCodes.Revoked);
        }

        if (tokenData.ExpiresAt <= _timeProvider.GetUtcNow())
        {
            return (null, RefreshTokenErrorCodes.Expired);
        }

        return (tokenData, null);
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
