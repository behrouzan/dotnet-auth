namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Represents an error that can occur while authenticating a password.
/// </summary>
public enum PasswordAuthenticationErrorCode
{
    /// <summary>
    /// The supplied credentials are invalid.
    /// </summary>
    InvalidCredentials = 1,

    /// <summary>
    /// The user is currently locked out.
    /// </summary>
    LockedOut = 2,

    /// <summary>
    /// The user is not allowed to sign in.
    /// </summary>
    NotAllowed = 3
}
