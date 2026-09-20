namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Locates users by one specific type of identifier.
/// </summary>
/// <typeparam name="TUser">The application user type.</typeparam>
public interface IUserIdentifierLookup<TUser>
    where TUser : class
{
    /// <summary>
    /// Gets the type of identifier supported by this lookup.
    /// </summary>
    UserIdentifierType IdentifierType { get; }

    /// <summary>
    /// Finds every user that matches the specified identifier value.
    /// </summary>
    /// <param name="identifier">The identifier value to look up.</param>
    /// <param name="cancellationToken">A token that can cancel the operation.</param>
    /// <returns>The users that match the identifier.</returns>
    Task<IReadOnlyCollection<TUser>> FindAsync(
        string identifier,
        CancellationToken cancellationToken = default);
}
