using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Behrouzan.Auth.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Behrouzan.Auth.AspNetCore.Tests.Authentication;

public sealed class AccessTokenManagerTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 24, 8, 30, 0, TimeSpan.Zero);

    [Fact]
    public void Create_ShouldWriteConfiguredStandardClaimsAndExpiration()
    {
        var lifetime = TimeSpan.FromMinutes(12);
        var manager = CreateManager(
            new TestSigningCredentialsProvider(CreateCredentials("key-one")),
            lifetime);

        var accessToken = manager.Create("canonical-subject");
        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(accessToken.Token);

        Assert.Equal("canonical-subject", jwt.Subject);
        Assert.Equal("https://issuer.example", jwt.Issuer);
        Assert.Equal("behrouzan-api", Assert.Single(jwt.Audiences));
        Assert.Equal(
            Now.ToUnixTimeSeconds().ToString(),
            jwt.Claims.Single(claim => claim.Type == JwtRegisteredClaimNames.Iat).Value);
        Assert.Equal(Now.Add(lifetime), accessToken.ExpiresAt);
        Assert.Equal(
            Now.Add(lifetime).ToUnixTimeSeconds(),
            jwt.Payload.Expiration);
        Assert.False(string.IsNullOrWhiteSpace(jwt.Id));
    }

    [Fact]
    public void Create_ShouldUseUniqueTokenIdentifierForEachToken()
    {
        var manager = CreateManager(
            new TestSigningCredentialsProvider(CreateCredentials("key-one")));

        var first = new JwtSecurityTokenHandler().ReadJwtToken(
            manager.Create("subject").Token);
        var second = new JwtSecurityTokenHandler().ReadJwtToken(
            manager.Create("subject").Token);

        Assert.NotEqual(first.Id, second.Id);
    }

    [Fact]
    public void Create_ShouldSignUsingCredentialsSuppliedByProvider()
    {
        var credentials = CreateCredentials("active-key");
        var manager = CreateManager(new TestSigningCredentialsProvider(credentials));
        var token = manager.Create("subject").Token;

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        var principal = handler.ValidateToken(
            token,
            CreateValidationParameters(credentials.Key),
            out var validatedToken);

        Assert.Equal("subject", principal.FindFirstValue(JwtRegisteredClaimNames.Sub));
        Assert.Equal(SecurityAlgorithms.HmacSha256, ((JwtSecurityToken)validatedToken).Header.Alg);
    }

    [Fact]
    public void Create_ShouldRequestSigningCredentialsForEachIssuance()
    {
        var firstCredentials = CreateCredentials("first-key");
        var secondCredentials = CreateCredentials("second-key");
        var provider = new TestSigningCredentialsProvider(
            firstCredentials,
            secondCredentials);
        var manager = CreateManager(provider);

        var firstToken = manager.Create("subject").Token;
        var secondToken = manager.Create("subject").Token;

        Assert.Equal(2, provider.CallCount);
        new JwtSecurityTokenHandler().ValidateToken(
            firstToken,
            CreateValidationParameters(firstCredentials.Key),
            out _);
        new JwtSecurityTokenHandler().ValidateToken(
            secondToken,
            CreateValidationParameters(secondCredentials.Key),
            out _);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Create_ShouldRejectInvalidSubject(string? subject)
    {
        var manager = CreateManager(
            new TestSigningCredentialsProvider(CreateCredentials("key-one")));

        Assert.ThrowsAny<ArgumentException>(() => manager.Create(subject!));
    }

    private static AccessTokenManager CreateManager(
        IAccessTokenSigningCredentialsProvider provider,
        TimeSpan? lifetime = null)
    {
        return new AccessTokenManager(
            provider,
            new FixedTimeProvider(Now),
            Options.Create(new AccessTokenOptions
            {
                Issuer = "https://issuer.example",
                Audience = "behrouzan-api",
                Lifetime = lifetime ?? TimeSpan.FromMinutes(5)
            }));
    }

    private static SigningCredentials CreateCredentials(string keyId)
    {
        var key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(
                $"test-signing-key-material-{keyId}".PadRight(64, 'x')))
        {
            KeyId = keyId
        };

        return new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }

    private static TokenValidationParameters CreateValidationParameters(SecurityKey key)
    {
        return new TokenValidationParameters
        {
            IssuerSigningKey = key,
            ValidIssuer = "https://issuer.example",
            ValidAudience = "behrouzan-api",
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = false,
            SignatureValidator = null
        };
    }

    private sealed class TestSigningCredentialsProvider
        : IAccessTokenSigningCredentialsProvider
    {
        private readonly Queue<SigningCredentials> _credentials;
        private SigningCredentials? _lastCredentials;

        public TestSigningCredentialsProvider(params SigningCredentials[] credentials)
        {
            _credentials = new Queue<SigningCredentials>(credentials);
        }

        public int CallCount { get; private set; }

        public SigningCredentials GetSigningCredentials()
        {
            CallCount++;

            if (_credentials.Count > 0)
            {
                _lastCredentials = _credentials.Dequeue();
            }

            return _lastCredentials!;
        }
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        private readonly DateTimeOffset _utcNow;

        public FixedTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow() => _utcNow;
    }
}
