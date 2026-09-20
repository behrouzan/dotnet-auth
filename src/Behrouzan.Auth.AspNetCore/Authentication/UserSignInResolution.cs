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

    public UserSignInResolutionStatus Status { get; }

    public TUser? User { get; }

    public static UserSignInResolution<TUser> Resolved(TUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        return new(
            UserSignInResolutionStatus.Resolved,
            user);
    }

    public static UserSignInResolution<TUser> NotFound()
    {
        return new(
            UserSignInResolutionStatus.NotFound,
            null);
    }

    public static UserSignInResolution<TUser> Ambiguous()
    {
        return new(
            UserSignInResolutionStatus.Ambiguous,
            null);
    }
}