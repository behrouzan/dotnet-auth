namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Defines a strategy for locating a user from a sign-in identifier.
/// </summary>
/// <typeparam name="TUser">The application user type.</typeparam>
public interface IUserSignInResolver<TUser>
    where TUser : class
{
    /// <summary>
    /// Attempts to locate a user from the specified sign-in identifier.
    /// </summary>
    /// <param name="identifier">
    /// The identifier supplied during sign-in.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the operation.
    /// </param>
    /// <returns>
    /// The matching user, or <see langword="null"/> when no user can be found.
    /// </returns>
    Task<UserSignInResolution<TUser>> ResolveAsync(
        string identifier,
        CancellationToken cancellationToken = default);
}