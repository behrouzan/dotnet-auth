using Microsoft.IdentityModel.Tokens;

namespace Sample.Api.TokenAuthentication;

internal sealed class SampleTokenAuthenticationOptions
{
    public const string SectionName = "TokenAuthentication";

    private const int MinimumSigningKeyBytes = 32;

    private SampleTokenAuthenticationOptions(
        string issuer,
        string audience,
        string algorithm,
        TimeSpan accessTokenLifetime,
        TimeSpan refreshTokenLifetime,
        SymmetricSecurityKey signingKey)
    {
        Issuer = issuer;
        Audience = audience;
        Algorithm = algorithm;
        AccessTokenLifetime = accessTokenLifetime;
        RefreshTokenLifetime = refreshTokenLifetime;
        SigningKey = signingKey;
    }

    public string Issuer { get; }

    public string Audience { get; }

    public string Algorithm { get; }

    public TimeSpan AccessTokenLifetime { get; }

    public TimeSpan RefreshTokenLifetime { get; }

    public SymmetricSecurityKey SigningKey { get; }

    public static SampleTokenAuthenticationOptions FromConfiguration(
        IConfigurationSection section)
    {
        var issuer = RequireNonEmpty(section, "Issuer");
        var audience = RequireNonEmpty(section, "Audience");
        var algorithm = RequireNonEmpty(section, "Algorithm");

        if (!string.Equals(
                algorithm,
                SecurityAlgorithms.HmacSha256,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{section.Path}:Algorithm must be '{SecurityAlgorithms.HmacSha256}'.");
        }

        var accessTokenLifetime = RequirePositiveTimeSpan(
            section,
            "AccessTokenLifetime");
        var refreshTokenLifetime = RequirePositiveTimeSpan(
            section,
            "RefreshTokenLifetime");
        var encodedKey = RequireNonEmpty(section, "SigningKey");
        byte[] keyBytes;

        try
        {
            keyBytes = Convert.FromBase64String(encodedKey);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException(
                $"{section.Path}:SigningKey must be a Base64-encoded key.",
                exception);
        }

        if (keyBytes.Length < MinimumSigningKeyBytes)
        {
            throw new InvalidOperationException(
                $"{section.Path}:SigningKey must contain at least {MinimumSigningKeyBytes} bytes.");
        }

        return new SampleTokenAuthenticationOptions(
            issuer,
            audience,
            algorithm,
            accessTokenLifetime,
            refreshTokenLifetime,
            new SymmetricSecurityKey(keyBytes));
    }

    private static string RequireNonEmpty(
        IConfigurationSection section,
        string key)
    {
        var value = section[key];

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(
                $"Required configuration '{section.Path}:{key}' is missing or empty.");
        }

        return value;
    }

    private static TimeSpan RequirePositiveTimeSpan(
        IConfigurationSection section,
        string key)
    {
        var value = RequireNonEmpty(section, key);

        if (!TimeSpan.TryParse(value, out var parsed) || parsed <= TimeSpan.Zero)
        {
            throw new InvalidOperationException(
                $"{section.Path}:{key} must be a positive TimeSpan.");
        }

        return parsed;
    }
}
