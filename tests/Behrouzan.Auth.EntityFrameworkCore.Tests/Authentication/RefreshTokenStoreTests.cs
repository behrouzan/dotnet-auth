using Behrouzan.Auth.Authentication;
using Behrouzan.Auth.EntityFrameworkCore.Authentication;
using Behrouzan.Auth.EntityFrameworkCore.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace Behrouzan.Auth.EntityFrameworkCore.Tests.Authentication;

public sealed class RefreshTokenStoreTests
{
    [Fact]
    public async Task InsertAsync_ShouldPersistToken_AndFindByHashShouldReturnIt()
    {
        await using var fixture = await CreateFixtureAsync();

        var store = CreateStore(fixture.Context);

        var userId = await AddUserAsync(fixture.Context);

        var token = CreateToken(
            userId,
            [1, 2, 3, 4]);

        await store.InsertAsync(token);

        var result =
            await store.FindByHashAsync(token.TokenHash);

        Assert.NotNull(result);
        Assert.Equal(token.TokenId, result.TokenId);
        Assert.Equal(token.UserId, result.UserId);
        Assert.Equal(token.ExpiresAt, result.ExpiresAt);
        Assert.Null(result.RevokedAt);
        Assert.Null(result.RevocationReason);
        Assert.Null(result.ReplacedByTokenId);
    }

    [Fact]
    public async Task FindByHashAsync_ShouldReturnNull_WhenTokenDoesNotExist()
    {
        await using var fixture = await CreateFixtureAsync();

        var store = CreateStore(fixture.Context);

        var result =
            await store.FindByHashAsync([99, 98, 97]);

        Assert.Null(result);
    }

    [Fact]
    public async Task SaveRevocationAsync_ShouldRevokeActiveToken()
    {
        await using var fixture = await CreateFixtureAsync();

        var store = CreateStore(fixture.Context);

        var userId = await AddUserAsync(fixture.Context);

        var token = CreateToken(
            userId,
            [10, 11, 12]);

        await store.InsertAsync(token);

        var revokedAt =
            new DateTimeOffset(
                2026, 9, 9,
                12, 0, 0,
                TimeSpan.Zero);

        await store.SaveRevocationAsync(
            new RefreshTokenRevocationData
            {
                TokenId = token.TokenId,
                RevokedAt = revokedAt,
                RevocationReason =
                    RefreshTokenRevocationReason.Logout
            });

        var result =
            await store.FindByHashAsync(token.TokenHash);

        Assert.NotNull(result);
        Assert.Equal(revokedAt, result.RevokedAt);
        Assert.Equal(
            RefreshTokenRevocationReason.Logout,
            result.RevocationReason);
    }

    [Fact]
    public async Task SaveRevocationAsync_ShouldNotOverwriteExistingRevocation()
    {
        await using var fixture = await CreateFixtureAsync();

        var store = CreateStore(fixture.Context);

        var userId = await AddUserAsync(fixture.Context);

        var token = CreateToken(
            userId,
            [20, 21, 22]);

        await store.InsertAsync(token);

        var securityRevokedAt =
            new DateTimeOffset(
                2026, 9, 9,
                10, 0, 0,
                TimeSpan.Zero);

        await store.SaveRevocationAsync(
            new RefreshTokenRevocationData
            {
                TokenId = token.TokenId,
                RevokedAt = securityRevokedAt,
                RevocationReason =
                    RefreshTokenRevocationReason.Security
            });

        await store.SaveRevocationAsync(
            new RefreshTokenRevocationData
            {
                TokenId = token.TokenId,
                RevokedAt = securityRevokedAt.AddHours(1),
                RevocationReason =
                    RefreshTokenRevocationReason.Logout
            });

        var result =
            await store.FindByHashAsync(token.TokenHash);

        Assert.NotNull(result);
        Assert.Equal(
            securityRevokedAt,
            result.RevokedAt);

        Assert.Equal(
            RefreshTokenRevocationReason.Security,
            result.RevocationReason);
    }

    [Fact]
    public async Task SaveRotationAsync_ShouldRevokeCurrentToken_AndPersistReplacement()
    {
        await using var fixture = await CreateFixtureAsync();

        var store = CreateStore(fixture.Context);

        var userId = await AddUserAsync(fixture.Context);

        var currentToken =
            CreateToken(
                userId,
                [30, 31, 32]);

        await store.InsertAsync(currentToken);

        var replacement =
            CreateToken(
                userId,
                [40, 41, 42]);

        var revokedAt =
            new DateTimeOffset(
                2026, 9, 9,
                13, 0, 0,
                TimeSpan.Zero);

        var rotation =
            new RefreshTokenRotationData
            {
                TokenId = currentToken.TokenId,
                RevokedAt = revokedAt,
                RevocationReason =
                    RefreshTokenRevocationReason.Rotated,
                ReplacedByTokenId =
                    replacement.TokenId
            };

        var result =
            await store.SaveRotationAsync(
                rotation,
                replacement);

        Assert.True(result.Succeeded);

        var oldToken =
            await store.FindByHashAsync(
                currentToken.TokenHash);

        Assert.NotNull(oldToken);
        Assert.Equal(revokedAt, oldToken.RevokedAt);
        Assert.Equal(
            RefreshTokenRevocationReason.Rotated,
            oldToken.RevocationReason);
        Assert.Equal(
            replacement.TokenId,
            oldToken.ReplacedByTokenId);

        var newToken =
            await store.FindByHashAsync(
                replacement.TokenHash);

        Assert.NotNull(newToken);
        Assert.Equal(
            replacement.TokenId,
            newToken.TokenId);
        Assert.Null(newToken.RevokedAt);
    }

    [Fact]
    public async Task SaveRotationAsync_ShouldRollbackReplacement_WhenCurrentTokenIsAlreadyRevoked()
    {
        await using var fixture = await CreateFixtureAsync();

        var store = CreateStore(fixture.Context);

        var userId = await AddUserAsync(fixture.Context);

        var currentToken =
            CreateToken(
                userId,
                [50, 51, 52]);

        await store.InsertAsync(currentToken);

        var originalRevokedAt =
            new DateTimeOffset(
                2026, 9, 9,
                14, 0, 0,
                TimeSpan.Zero);

        await store.SaveRevocationAsync(
            new RefreshTokenRevocationData
            {
                TokenId = currentToken.TokenId,
                RevokedAt = originalRevokedAt,
                RevocationReason =
                    RefreshTokenRevocationReason.Security
            });

        var replacement =
            CreateToken(
                userId,
                [60, 61, 62]);

        var rotation =
            new RefreshTokenRotationData
            {
                TokenId = currentToken.TokenId,
                RevokedAt = originalRevokedAt.AddMinutes(1),
                RevocationReason =
                    RefreshTokenRevocationReason.Rotated,
                ReplacedByTokenId =
                    replacement.TokenId
            };

        var result =
            await store.SaveRotationAsync(
                rotation,
                replacement);

        Assert.False(result.Succeeded);

        Assert.Equal(
            originalRevokedAt,
            result.RevokedAt);

        Assert.Equal(
            RefreshTokenRevocationReason.Security,
            result.RevocationReason);

        Assert.Null(result.ReplacedByTokenId);

        var replacementInDatabase =
            await store.FindByHashAsync(
                replacement.TokenHash);

        Assert.Null(replacementInDatabase);
    }

    [Fact]
    public async Task SaveRotationAsync_ShouldReturnExistingRotationMetadata_WhenTokenWasAlreadyRotated()
    {
        await using var fixture = await CreateFixtureAsync();

        var store = CreateStore(fixture.Context);

        var userId = await AddUserAsync(fixture.Context);

        var currentToken =
            CreateToken(
                userId,
                [70, 71, 72]);

        await store.InsertAsync(currentToken);

        var firstReplacement =
            CreateToken(
                userId,
                [80, 81, 82]);

        var firstRevokedAt =
            new DateTimeOffset(
                2026, 9, 9,
                15, 0, 0,
                TimeSpan.Zero);

        var firstRotation =
            new RefreshTokenRotationData
            {
                TokenId = currentToken.TokenId,
                RevokedAt = firstRevokedAt,
                RevocationReason =
                    RefreshTokenRevocationReason.Rotated,
                ReplacedByTokenId =
                    firstReplacement.TokenId
            };

        var firstResult =
            await store.SaveRotationAsync(
                firstRotation,
                firstReplacement);

        Assert.True(firstResult.Succeeded);

        var secondReplacement =
            CreateToken(
                userId,
                [90, 91, 92]);

        var secondRotation =
            new RefreshTokenRotationData
            {
                TokenId = currentToken.TokenId,
                RevokedAt = firstRevokedAt.AddMinutes(1),
                RevocationReason =
                    RefreshTokenRevocationReason.Rotated,
                ReplacedByTokenId =
                    secondReplacement.TokenId
            };

        var secondResult =
            await store.SaveRotationAsync(
                secondRotation,
                secondReplacement);

        Assert.False(secondResult.Succeeded);

        Assert.Equal(
            firstRevokedAt,
            secondResult.RevokedAt);

        Assert.Equal(
            RefreshTokenRevocationReason.Rotated,
            secondResult.RevocationReason);

        Assert.Equal(
            firstReplacement.TokenId,
            secondResult.ReplacedByTokenId);

        var secondReplacementInDatabase =
            await store.FindByHashAsync(
                secondReplacement.TokenHash);

        Assert.Null(secondReplacementInDatabase);
    }

    private static RefreshTokenStore<TestDbContext, Guid>
        CreateStore(TestDbContext context)
    {
        return new RefreshTokenStore<
            TestDbContext,
            Guid>(context);
    }

    private static RefreshTokenCreateData<Guid> CreateToken(
        Guid userId,
        byte[] tokenHash)
    {
        var createdAt =
            new DateTimeOffset(
                2026, 9, 9,
                10, 0, 0,
                TimeSpan.Zero);

        return new RefreshTokenCreateData<Guid>
        {
            TokenId = Guid.NewGuid(),
            UserId = userId,
            TokenHash = tokenHash,
            CreatedAt = createdAt,
            ExpiresAt = createdAt.AddDays(30)
        };
    }

    private static async Task<Guid> AddUserAsync(
        TestDbContext context)
    {
        var user = new TestUser
        {
            Id = Guid.NewGuid(),
            UserName = Guid.NewGuid().ToString()
        };

        context.Users.Add(user);

        await context.SaveChangesAsync();

        return user.Id;
    }

    private static async Task<TestFixture>
        CreateFixtureAsync()
    {
        var connection =
            new SqliteConnection("Data Source=:memory:");

        await connection.OpenAsync();

        var options =
            new DbContextOptionsBuilder<TestDbContext>()
                .UseSqlite(connection)
                .Options;

        var context =
            new TestDbContext(options);

        await context.Database.EnsureCreatedAsync();

        return new TestFixture(
            connection,
            context);
    }

    private sealed class TestUser
        : IdentityUser<Guid>
    {
    }

    private sealed class TestRole
        : IdentityRole<Guid>
    {
    }

    private sealed class TestDbContext
        : IdentityDbContext<
            TestUser,
            TestRole,
            Guid>
    {
        public TestDbContext(
            DbContextOptions<TestDbContext> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(
            ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.ConfigureBehrouzanAuth<
                TestUser,
                TestRole,
                Guid>();
        }
    }

    private sealed class TestFixture
        : IAsyncDisposable
    {
        public TestFixture(
            SqliteConnection connection,
            TestDbContext context)
        {
            Connection = connection;
            Context = context;
        }

        public SqliteConnection Connection { get; }

        public TestDbContext Context { get; }

        public async ValueTask DisposeAsync()
        {
            await Context.DisposeAsync();
            await Connection.DisposeAsync();
        }
    }
}