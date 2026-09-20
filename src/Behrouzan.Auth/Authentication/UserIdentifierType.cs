namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Identifies a single type of user identifier supported by a lookup.
/// </summary>
public readonly record struct UserIdentifierType
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserIdentifierType"/> struct.
    /// </summary>
    /// <param name="value">The stable identifier type value.</param>
    public UserIdentifierType(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }

    /// <summary>
    /// Gets the stable identifier type value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// Identifies a user's phone number.
    /// </summary>
    public static UserIdentifierType PhoneNumber { get; } = new("phone-number");
}
