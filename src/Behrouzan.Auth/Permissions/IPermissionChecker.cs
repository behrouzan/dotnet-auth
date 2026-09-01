namespace Behrouzan.Auth.Permissions;

/// <summary>
/// Checks whether permissions are granted to users.
/// </summary>
/// <typeparam name="TKey">
/// The type used to identify users.
/// </typeparam>
public interface IPermissionChecker<TKey>
    where TKey : notnull
{
    /// <summary>
    /// Determines whether the specified permission is granted to a user.
    /// </summary>
    /// <param name="userId">
    /// The identifier of the user whose permission should be checked.
    /// </param>
    /// <param name="permissionName">
    /// The unique name of the permission to check.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the permission is granted;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    Task<bool> IsGrantedAsync(
        TKey userId,
        string permissionName,
        CancellationToken cancellationToken = default);
}