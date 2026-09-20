namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Identifies the built-in types of values that can be used to locate
/// a user during sign-in.
/// </summary>
[Flags]
public enum SignInIdentifier
{
    /// <summary>
    /// No built-in sign-in identifier is enabled.
    /// </summary>
    None = 0,

    /// <summary>
    /// Allows users to be located by username.
    /// </summary>
    UserName = 1,

    /// <summary>
    /// Allows users to be located by email address.
    /// </summary>
    Email = 2,

    /// <summary>
    /// Allows users to be located by phone number.
    /// </summary>
    PhoneNumber = 4
}
