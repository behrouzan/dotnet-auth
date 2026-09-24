namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>Represents an error that can occur while refreshing a token pair.</summary>
public enum TokenRefreshErrorCode
{
    /// <summary>The supplied refresh token is invalid or its owner no longer exists.</summary>
    InvalidToken = 1,
    /// <summary>The refresh token has expired.</summary>
    Expired = 2,
    /// <summary>The refresh token has been revoked.</summary>
    Revoked = 3,
    /// <summary>A previously rotated refresh token was reused.</summary>
    ReuseDetected = 4,
    /// <summary>The refresh token changed concurrently.</summary>
    ConcurrencyConflict = 5,
    /// <summary>The current user is locked out.</summary>
    LockedOut = 6,
    /// <summary>The current user is not allowed to sign in.</summary>
    NotAllowed = 7,
    /// <summary>The current user must complete two-factor authentication.</summary>
    RequiresTwoFactor = 8
}
