namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Provides configuration options for refresh token operations.
/// </summary>
public sealed class RefreshTokenOptions
{
    /// <summary>
    /// Gets or sets the lifetime of newly issued refresh tokens.
    /// </summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromDays(30);
}