using Behrouzan.Auth.Authentication;
using Microsoft.Extensions.Options;

namespace Behrouzan.Auth.Tests.Authentication;

public sealed class RefreshTokenManagerTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 8, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task RefreshAsync_WhenTokenIsEmpty_ReturnsInvalidToken()
    {
        var store = new FakeRefreshTokenStore<Guid>();
        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Token);
        Assert.Equal(
            RefreshTokenErrorCodes.InvalidToken,
            result.ErrorCode);
    }

    [Fact]
    public async Task RefreshAsync_WhenTokenIsWhitespace_ReturnsInvalidToken()
    {
        var store = new FakeRefreshTokenStore<Guid>();
        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("   ");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Token);
        Assert.Equal(
            RefreshTokenErrorCodes.InvalidToken,
            result.ErrorCode);
    }

    [Fact]
    public async Task RefreshAsync_WhenTokenIsNotFound_ReturnsInvalidToken()
    {
        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = null
        };

        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Token);
        Assert.Equal(
            RefreshTokenErrorCodes.InvalidToken,
            result.ErrorCode);
    }

    [Fact]
    public async Task RefreshAsync_WhenTokenWasRotated_ReturnsReuseDetected()
    {
        var replacementTokenId = Guid.NewGuid();

        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = new RefreshTokenData<Guid>
            {
                TokenId = Guid.NewGuid(),
                UserId = Guid.NewGuid(),
                ExpiresAt = Now.AddDays(10),
                RevokedAt = Now.AddMinutes(-5),
                RevocationReason = RefreshTokenRevocationReason.Rotated,
                ReplacedByTokenId = replacementTokenId
            }
        };

        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Token);
        Assert.Equal(
            RefreshTokenErrorCodes.ReuseDetected,
            result.ErrorCode);
    }

    [Fact]
    public async Task RefreshAsync_WhenTokenIsRevoked_ReturnsRevoked()
    {
        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = new RefreshTokenData<Guid>
            {
                TokenId = Guid.NewGuid(),
                UserId = Guid.NewGuid(),
                ExpiresAt = Now.AddDays(10),
                RevokedAt = Now.AddMinutes(-5),
                RevocationReason = RefreshTokenRevocationReason.Logout
            }
        };

        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Token);
        Assert.Equal(
            RefreshTokenErrorCodes.Revoked,
            result.ErrorCode);
    }

    [Fact]
    public async Task ValidateAndRefreshAsync_WhenTokenWasRevokedByLogoutAll_ReturnRevoked()
    {
        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = new RefreshTokenData<Guid>
            {
                TokenId = Guid.NewGuid(),
                UserId = Guid.NewGuid(),
                ExpiresAt = Now.AddDays(10),
                RevokedAt = Now.AddMinutes(-1),
                RevocationReason = RefreshTokenRevocationReason.LogoutAll
            }
        };
        var manager = CreateManager(store);

        var validation = await manager.ValidateAsync("refresh-token");
        var renewal = await manager.RefreshAsync("refresh-token");

        Assert.False(validation.IsSuccess);
        Assert.Equal(RefreshTokenErrorCodes.Revoked, validation.ErrorCode);
        Assert.False(renewal.IsSuccess);
        Assert.Equal(RefreshTokenErrorCodes.Revoked, renewal.ErrorCode);
    }

    [Fact]
    public async Task RefreshAsync_WhenTokenIsExpired_ReturnsExpired()
    {
        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = new RefreshTokenData<Guid>
            {
                TokenId = Guid.NewGuid(),
                UserId = Guid.NewGuid(),
                ExpiresAt = Now.AddMinutes(-1)
            }
        };

        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Token);
        Assert.Equal(
            RefreshTokenErrorCodes.Expired,
            result.ErrorCode);
    }

    [Fact]
    public async Task RefreshAsync_WhenTokenExpiresExactlyNow_ReturnsExpired()
    {
        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = new RefreshTokenData<Guid>
            {
                TokenId = Guid.NewGuid(),
                UserId = Guid.NewGuid(),
                ExpiresAt = Now
            }
        };

        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Equal(
            RefreshTokenErrorCodes.Expired,
            result.ErrorCode);
    }

    [Fact]
    public async Task RefreshAsync_WhenRotationSucceeds_ReturnsNewToken()
    {
        var userId = Guid.NewGuid();
        var currentTokenId = Guid.NewGuid();

        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = new RefreshTokenData<Guid>
            {
                TokenId = currentTokenId,
                UserId = userId,
                ExpiresAt = Now.AddDays(10)
            },
            RotationResult = new RefreshTokenRotationResult
            {
                Succeeded = true
            }
        };

        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("refresh-token");

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Token);
        Assert.NotEmpty(result.Token);
        Assert.Null(result.ErrorCode);
        Assert.Equal(userId, result.UserId);

        Assert.NotNull(store.LastNewToken);
        Assert.NotNull(store.LastRotation);

        Assert.Equal(userId, store.LastNewToken.UserId);
        Assert.Equal(Now, store.LastNewToken.CreatedAt);
        Assert.Equal(Now.AddDays(30), store.LastNewToken.ExpiresAt);

        Assert.NotEqual(Guid.Empty, store.LastNewToken.TokenId);
        Assert.NotEmpty(store.LastNewToken.TokenHash);

        Assert.Equal(currentTokenId, store.LastRotation.TokenId);
        Assert.Equal(Now, store.LastRotation.RevokedAt);
        Assert.Equal(
            RefreshTokenRevocationReason.Rotated,
            store.LastRotation.RevocationReason);

    }

    [Fact]
    public async Task ValidateAsync_WhenTokenIsActive_ReturnsStoredOwnerWithoutRotation()
    {
        var userId = Guid.NewGuid();
        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = new RefreshTokenData<Guid>
            {
                TokenId = Guid.NewGuid(),
                UserId = userId,
                ExpiresAt = Now.AddDays(10)
            }
        };
        var manager = CreateManager(store);

        var result = await manager.ValidateAsync("refresh-token");

        Assert.True(result.IsSuccess);
        Assert.Equal(userId, result.UserId);
        Assert.Null(result.ErrorCode);
        Assert.Null(store.LastRotation);
        Assert.Null(store.LastNewToken);
    }

    [Theory]
    [InlineData("invalid", RefreshTokenErrorCodes.InvalidToken)]
    [InlineData("expired", RefreshTokenErrorCodes.Expired)]
    [InlineData("revoked", RefreshTokenErrorCodes.Revoked)]
    [InlineData("reused", RefreshTokenErrorCodes.ReuseDetected)]
    public async Task ValidateAsync_ShouldPreserveErrorsWithoutRotation(
        string state,
        string expectedError)
    {
        var token = state == "invalid"
            ? null
            : new RefreshTokenData<Guid>
            {
                TokenId = Guid.NewGuid(),
                UserId = Guid.NewGuid(),
                ExpiresAt = state == "expired" ? Now : Now.AddDays(1),
                RevokedAt = state is "revoked" or "reused" ? Now.AddMinutes(-1) : null,
                RevocationReason = state == "reused"
                    ? RefreshTokenRevocationReason.Rotated
                    : state == "revoked" ? RefreshTokenRevocationReason.Logout : null,
                ReplacedByTokenId = state == "reused" ? Guid.NewGuid() : null
            };
        var store = new FakeRefreshTokenStore<Guid> { TokenToReturn = token };
        var manager = CreateManager(store);

        var result = await manager.ValidateAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Equal(expectedError, result.ErrorCode);
        Assert.Null(store.LastRotation);
        Assert.Null(store.LastNewToken);
    }

    [Fact]
    public async Task RefreshAsync_WhenConcurrentRequestAlreadyRotatedToken_ReturnsReuseDetected()
    {
        var replacementTokenId = Guid.NewGuid();

        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = CreateActiveToken(),
            RotationResult = new RefreshTokenRotationResult
            {
                Succeeded = false,
                RevokedAt = Now,
                RevocationReason = RefreshTokenRevocationReason.Rotated,
                ReplacedByTokenId = replacementTokenId
            }
        };

        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Token);
        Assert.Equal(
            RefreshTokenErrorCodes.ReuseDetected,
            result.ErrorCode);
    }

    [Fact]
    public async Task RefreshAsync_WhenTokenIsRevokedDuringRotation_ReturnsRevoked()
    {
        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = CreateActiveToken(),
            RotationResult = new RefreshTokenRotationResult
            {
                Succeeded = false,
                RevokedAt = Now,
                RevocationReason = RefreshTokenRevocationReason.Logout
            }
        };

        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Token);
        Assert.Equal(
            RefreshTokenErrorCodes.Revoked,
            result.ErrorCode);
    }

    [Fact]
    public async Task RefreshAsync_WhenRotationFailsWithoutRevocationState_ReturnsConcurrencyConflict()
    {
        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = CreateActiveToken(),
            RotationResult = new RefreshTokenRotationResult
            {
                Succeeded = false
            }
        };

        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Token);
        Assert.Equal(
            RefreshTokenErrorCodes.ConcurrencyConflict,
            result.ErrorCode);
    }

    [Fact]
    public async Task RefreshAsync_WhenTokenExpiresAtAtomicRotation_ReturnsExpired()
    {
        var store = new FakeRefreshTokenStore<Guid>
        {
            TokenToReturn = CreateActiveToken(),
            RotationResult = new RefreshTokenRotationResult
            {
                Succeeded = false,
                ExpiresAt = Now
            }
        };
        var manager = CreateManager(store);

        var result = await manager.RefreshAsync("refresh-token");

        Assert.False(result.IsSuccess);
        Assert.Null(result.Token);
        Assert.Equal(RefreshTokenErrorCodes.Expired, result.ErrorCode);
    }

    [Fact]
    public async Task RevokeAllAsync_ShouldUseCurrentTimeAndLogoutAllReason()
    {
        var userId = Guid.NewGuid();
        var store = new FakeRefreshTokenStore<Guid>();
        var manager = CreateManager(store);

        await manager.RevokeAllAsync(userId);
        await manager.RevokeAllAsync(userId);

        Assert.Equal(2, store.RevokeAllCallCount);
        Assert.Equal(userId, store.LastRevokedUserId);
        Assert.Equal(Now, store.LastRevokeAllAt);
        Assert.Equal(
            RefreshTokenRevocationReason.LogoutAll,
            store.LastRevokeAllReason);
    }

    private static RefreshTokenManager<Guid> CreateManager(
        FakeRefreshTokenStore<Guid> store)
    {
        var options = Options.Create(
            new RefreshTokenOptions
            {
                Lifetime = TimeSpan.FromDays(30)
            });

        return new RefreshTokenManager<Guid>(
            store,
            new RefreshTokenHasher(),
            new RefreshTokenGenerator(),
            new FixedTimeProvider(Now),
            options);
    }

    private static RefreshTokenData<Guid> CreateActiveToken()
    {
        return new RefreshTokenData<Guid>
        {
            TokenId = Guid.NewGuid(),
            UserId = Guid.NewGuid(),
            ExpiresAt = Now.AddDays(10)
        };
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utcNow;

        public FixedTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow()
        {
            return _utcNow;
        }
    }

    private sealed class FakeRefreshTokenStore<TKey>
        : IRefreshTokenStore<TKey>
        where TKey : notnull
    {
        public RefreshTokenData<TKey>? TokenToReturn { get; set; }

        public RefreshTokenRotationResult RotationResult { get; set; } =
            new RefreshTokenRotationResult
            {
                Succeeded = true
            };

        public RefreshTokenRotationData? LastRotation { get; private set; }

        public RefreshTokenCreateData<TKey>? LastNewToken { get; private set; }

        public int RevokeAllCallCount { get; private set; }

        public TKey? LastRevokedUserId { get; private set; }

        public DateTimeOffset? LastRevokeAllAt { get; private set; }

        public RefreshTokenRevocationReason? LastRevokeAllReason { get; private set; }

        public Task InsertAsync(
            RefreshTokenCreateData<TKey> refreshToken,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<RefreshTokenData<TKey>?> FindByHashAsync(
            byte[] tokenHash,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(TokenToReturn);
        }

        public Task SaveRevocationAsync(
            RefreshTokenRevocationData refreshToken,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task RevokeAllAsync(
            TKey userId,
            DateTimeOffset revokedAt,
            RefreshTokenRevocationReason revocationReason,
            CancellationToken cancellationToken = default)
        {
            RevokeAllCallCount++;
            LastRevokedUserId = userId;
            LastRevokeAllAt = revokedAt;
            LastRevokeAllReason = revocationReason;
            return Task.CompletedTask;
        }

        public Task<RefreshTokenRotationResult> SaveRotationAsync(
            RefreshTokenRotationData currentToken,
            RefreshTokenCreateData<TKey> newToken,
            CancellationToken cancellationToken = default)
        {
            LastRotation = currentToken;
            LastNewToken = newToken;

            return Task.FromResult(RotationResult);
        }
    }
}
