namespace Behrouzan.Auth.Permissions;

/// <summary>
/// Defines persistence operations for managing permission grants assigned to roles.
/// </summary>
/// <typeparam name="TKey">
/// The type of the role identifier.
/// </typeparam>
public interface IRolePermissionGrantStore<TKey>
    where TKey : notnull
{
    /// <summary>
    /// Grants the specified permission to a role.
    /// </summary>
    /// <param name="roleId">
    /// The identifier of the role.
    /// </param>
    /// <param name="permissionName">
    /// The name of the permission to grant.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    Task GrantAsync(
        TKey roleId,
        string permissionName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the specified permission from a role.
    /// </summary>
    /// <param name="roleId">
    /// The identifier of the role.
    /// </param>
    /// <param name="permissionName">
    /// The name of the permission to revoke.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    Task RevokeAsync(
        TKey roleId,
        string permissionName,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the permissions granted directly to the specified role.
    /// </summary>
    /// <param name="roleId">
    /// The identifier of the role.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// The names of the permissions granted directly to the role.
    /// </returns>
    Task<IReadOnlyCollection<string>> GetPermissionsAsync(
        TKey roleId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Replaces all permissions currently granted to the specified role
    /// with the provided set of permissions.
    /// </summary>
    /// <param name="roleId">
    /// The identifier of the role.
    /// </param>
    /// <param name="permissionNames">
    /// The names of the permissions that should be granted to the role.
    /// An empty collection removes all permissions from the role.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    Task SetPermissionsAsync(
        TKey roleId,
        IReadOnlyCollection<string> permissionNames,
        CancellationToken cancellationToken = default);
}