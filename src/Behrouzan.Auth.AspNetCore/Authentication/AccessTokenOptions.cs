namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Provides configuration for access-token issuance.
/// </summary>
public sealed class AccessTokenOptions
{
    /// <summary>
    /// Gets or sets the issuer written to issued access tokens.
    /// </summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the audience written to issued access tokens.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the lifetime of issued access tokens.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(15);
}
