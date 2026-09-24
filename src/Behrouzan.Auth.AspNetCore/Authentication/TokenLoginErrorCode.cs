namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Represents an error that can occur during token login.
/// </summary>
public enum TokenLoginErrorCode
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
    /// The user must complete two-factor authentication before tokens can be issued.
    /// </summary>
    RequiresTwoFactor = 4,

    /// <summary>
    /// The refresh token could not be created, so no token pair is returned.
    /// </summary>
    RefreshTokenCreationFailed = 5
}
