using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Issues signed JWT access tokens for canonical subjects.
/// </summary>
public sealed class AccessTokenManager
{
    private readonly IAccessTokenSigningCredentialsProvider _signingCredentialsProvider;
    private readonly TimeProvider _timeProvider;
    private readonly AccessTokenOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="AccessTokenManager"/> class.
    /// </summary>
    /// <param name="signingCredentialsProvider">The provider of current signing credentials.</param>
    /// <param name="timeProvider">The source of the current time.</param>
    /// <param name="options">The configured access-token options.</param>
    public AccessTokenManager(
        IAccessTokenSigningCredentialsProvider signingCredentialsProvider,
        TimeProvider timeProvider,
        IOptions<AccessTokenOptions> options)
    {
        _signingCredentialsProvider = signingCredentialsProvider;
        _timeProvider = timeProvider;
        _options = options.Value;
    }

    /// <summary>
    /// Creates a signed JWT access token for the supplied canonical subject.
    /// </summary>
    /// <param name="subject">The canonical, non-empty subject for the token.</param>
    /// <returns>The encoded access token and its expiration time.</returns>
    public AccessToken Create(string subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        var issuedAt = _timeProvider.GetUtcNow();
        var expiresAt = issuedAt.Add(_options.Lifetime);
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, subject),
            new Claim(
                JwtRegisteredClaimNames.Iat,
                EpochTime.GetIntDate(issuedAt.UtcDateTime).ToString(),
                ClaimValueTypes.Integer64),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N"))
        };

        var jwt = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: null,
            expires: expiresAt.UtcDateTime,
            signingCredentials: _signingCredentialsProvider.GetSigningCredentials());

        return new AccessToken(
            new JwtSecurityTokenHandler().WriteToken(jwt),
            expiresAt);
    }
}
