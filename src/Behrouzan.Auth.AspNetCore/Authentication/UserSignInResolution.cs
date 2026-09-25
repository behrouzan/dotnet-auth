namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Represents the result of resolving a sign-in identifier to a user.
/// </summary>
public sealed class UserSignInResolution<TUser>
    where TUser : class
{
    private UserSignInResolution(
        UserSignInResolutionStatus status,
        TUser? user)
    {
        Status = status;
        User = user;
    }

    /// <summary>Gets the outcome of resolving the identifier.</summary>
    public UserSignInResolutionStatus Status { get; }

    /// <summary>Gets the resolved user when the status is <see cref="UserSignInResolutionStatus.Resolved"/>.</summary>
    public TUser? User { get; }

    /// <summary>Creates a successful resolution for the specified user.</summary>
    /// <param name="user">The resolved user.</param>
    /// <returns>A successful resolution.</returns>
    public static UserSignInResolution<TUser> Resolved(TUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        return new(
            UserSignInResolutionStatus.Resolved,
            user);
    }

    /// <summary>Creates a resolution indicating that no user was found.</summary>
    /// <returns>A not-found resolution.</returns>
    public static UserSignInResolution<TUser> NotFound()
    {
        return new(
            UserSignInResolutionStatus.NotFound,
            null);
    }

    /// <summary>Creates a resolution indicating that more than one user matched.</summary>
    /// <returns>An ambiguous resolution.</returns>
    public static UserSignInResolution<TUser> Ambiguous()
    {
        return new(
            UserSignInResolutionStatus.Ambiguous,
            null);
    }
}
