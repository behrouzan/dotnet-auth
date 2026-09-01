namespace Behrouzan.Auth.Permissions;

/// <summary>
/// Provides access to permissions granted to users.
/// </summary>
/// <typeparam name="TKey">
/// The type used to identify users.
/// </typeparam>
public interface IPermissionGrantStore<TKey>
    where TKey : notnull
{
    /// <summary>
    /// Gets the effective permissions granted to the specified user.
    /// </summary>
    /// <param name="userId">
    /// The identifier of the user.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// The names of the permissions granted to the user.
    /// </returns>
    Task<IReadOnlyCollection<string>> GetGrantedPermissionsAsync(
        TKey userId,
        CancellationToken cancellationToken = default);
}