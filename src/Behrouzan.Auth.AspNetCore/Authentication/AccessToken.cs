namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Represents an issued access token and its expiration time.
/// </summary>
public sealed class AccessToken
{
    internal AccessToken(string token, DateTimeOffset expiresAt)
    {
        Token = token;
        ExpiresAt = expiresAt;
    }

    /// <summary>
    /// Gets the encoded access token.
    /// </summary>
    public string Token { get; }

    /// <summary>
    /// Gets the UTC time at which the access token expires.
    /// </summary>
    public DateTimeOffset ExpiresAt { get; }
}
