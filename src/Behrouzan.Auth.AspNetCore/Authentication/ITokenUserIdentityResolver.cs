namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Resolves an authenticated user to its refresh-token identifier and canonical JWT subject.
/// </summary>
/// <typeparam name="TUser">The application user type.</typeparam>
/// <typeparam name="TKey">The type of the persisted user identifier.</typeparam>
public interface ITokenUserIdentityResolver<TUser, TKey>
    where TUser : class
    where TKey : notnull
{
    /// <summary>
    /// Resolves the token identity for the specified user.
    /// </summary>
    /// <param name="user">The authenticated user.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the operation.</param>
    /// <returns>The user's typed identifier and canonical Identity subject.</returns>
    /// <remarks>
    /// Implementations must derive both values from the same <typeparamref name="TUser"/>
    /// instance: <see cref="TokenUserIdentity{TKey}.UserId"/> must identify that user in
    /// refresh-token persistence, and <see cref="TokenUserIdentity{TKey}.Subject"/> must be
    /// the canonical Identity user ID for that user. The token-login manager verifies the
    /// canonical subject, but it cannot generically prove the semantic relationship between
    /// an arbitrary <typeparamref name="TKey"/> value and the user.
    /// </remarks>
    Task<TokenUserIdentity<TKey>> ResolveAsync(
        TUser user,
        CancellationToken cancellationToken = default);
}
