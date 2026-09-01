using System.Security.Claims;

namespace Behrouzan.Auth.AspNetCore.Users;

/// <summary>
/// Resolves the identifier of the authenticated user
/// from a claims principal.
/// </summary>
/// <typeparam name="TKey">
/// The type used to identify users.
/// </typeparam>
public interface IUserIdResolver<TKey>
    where TKey : notnull
{
    /// <summary>
    /// Attempts to resolve the user identifier
    /// from the specified claims principal.
    /// </summary>
    /// <param name="principal">
    /// The claims principal representing the current user.
    /// </param>
    /// <param name="userId">
    /// When this method returns <see langword="true"/>,
    /// contains the resolved user identifier.
    /// </param>
    /// <returns>
    /// <see langword="true"/> when a valid user identifier
    /// was resolved; otherwise, <see langword="false"/>.
    /// </returns>
    bool TryResolve(
        ClaimsPrincipal principal,
        out TKey userId);
}