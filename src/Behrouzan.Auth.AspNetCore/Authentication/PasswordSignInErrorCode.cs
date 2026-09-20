namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Represents an error that can occur during password sign-in.
/// </summary>
public enum PasswordSignInErrorCode
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
    NotAllowed = 3,

    /// <summary>
    /// The sign-in requires two-factor authentication.
    /// </summary>
    RequiresTwoFactor = 4
}