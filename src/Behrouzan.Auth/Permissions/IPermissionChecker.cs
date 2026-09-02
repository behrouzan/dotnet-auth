namespace Behrouzan.Auth.Permissions;

/// <summary>
/// Provides permission checks for a user.
/// </summary>
/// <typeparam name="TKey">
/// The type of the user identifier.
/// </typeparam>
public interface IPermissionChecker<TKey>
    where TKey : notnull
{
    /// <summary>
    /// Determines whether the specified user is granted
    /// the specified permission.
    /// </summary>
    /// <param name="userId">
    /// The identifier of the user.
    /// </param>
    /// <param name="permissionName">
    /// The name of the permission to check.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the operation.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the permission is granted;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="permissionName"/> is null,
    /// empty, or consists only of white-space characters.
    /// </exception>
    Task<bool> IsGrantedAsync(
        TKey userId,
        string permissionName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether the specified user is granted
    /// at least one of the specified permissions.
    /// </summary>
    /// <param name="userId">
    /// The identifier of the user.
    /// </param>
    /// <param name="permissionNames">
    /// The permission names to check.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the operation.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if at least one defined permission
    /// is granted; otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="permissionNames"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when no permission names are provided or when any
    /// permission name is null, empty, or consists only of white-space
    /// characters.
    /// </exception>
    Task<bool> IsAnyGrantedAsync(
        TKey userId,
        IEnumerable<string> permissionNames,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Determines whether the specified user is granted
    /// all of the specified permissions.
    /// </summary>
    /// <param name="userId">
    /// The identifier of the user.
    /// </param>
    /// <param name="permissionNames">
    /// The permission names to check.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the operation.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if all specified permissions are defined
    /// and granted; otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="permissionNames"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when no permission names are provided or when any
    /// permission name is null, empty, or consists only of white-space
    /// characters.
    /// </exception>
    Task<bool> AreAllGrantedAsync(
        TKey userId,
        IEnumerable<string> permissionNames,
        CancellationToken cancellationToken = default);
}