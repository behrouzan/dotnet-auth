namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Represents the outcome of resolving a sign-in identifier.
/// </summary>
public enum UserSignInResolutionStatus
{
    /// <summary>No user matched the identifier.</summary>
    NotFound = 0,

    /// <summary>Exactly one user matched the identifier.</summary>
    Resolved = 1,

    /// <summary>More than one user matched the identifier.</summary>
    Ambiguous = 2
}
