namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Specifies the reason a refresh token was revoked.
/// </summary>
public enum RefreshTokenRevocationReason
{
    /// <summary>
    /// The token was revoked because the user logged out.
    /// </summary>
    Logout = 1,

    /// <summary>
    /// The token was revoked as part of refresh token rotation.
    /// </summary>
    Rotated = 2,

    /// <summary>
    /// The token was revoked for security reasons.
    /// </summary>
    Security = 3,

    /// <summary>
    /// The token was revoked because the user logged out from all sessions.
    /// </summary>
    LogoutAll = 4
}
