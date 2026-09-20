namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Represents the outcome of resolving a sign-in identifier.
/// </summary>
public enum UserSignInResolutionStatus
{
    NotFound = 0,
    Resolved = 1,
    Ambiguous = 2
}