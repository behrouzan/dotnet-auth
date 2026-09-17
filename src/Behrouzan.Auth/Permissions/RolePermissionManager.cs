namespace Behrouzan.Auth.Permissions;

/// <summary>
/// Provides operations for managing permissions assigned to roles.
/// </summary>
/// <typeparam name="TKey">The type of the role identifier.</typeparam>
public sealed class RolePermissionManager<TKey>
    where TKey : notnull
{
    private readonly PermissionDefinitionCatalog _catalog;
    private readonly IRolePermissionGrantStore<TKey> _store;

    /// <summary>
    /// Initializes a new instance of the <see cref="RolePermissionManager{TKey}"/> class.
    /// </summary>
    /// <param name="catalog">The catalog containing the defined permissions.</param>
    /// <param name="store">The store used to persist role permission grants.</param>
    public RolePermissionManager(
        PermissionDefinitionCatalog catalog,
        IRolePermissionGrantStore<TKey> store)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(store);

        _catalog = catalog;
        _store = store;
    }

    /// <summary>
    /// Grants a permission to the specified role.
    /// </summary>
    /// <param name="roleId">The identifier of the role.</param>
    /// <param name="permissionName">The name of the permission to grant.</param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// A result indicating whether the operation succeeded.
    /// </returns>
    public async Task<PermissionManagementResult> GrantAsync(
        TKey roleId,
        string permissionName,
        CancellationToken cancellationToken = default)
    {
        if (!_catalog.TryGetPermission(permissionName, out _))
        {
            return PermissionManagementResult.Failure(
                PermissionManagementErrorCode.UnknownPermission);
        }

        await _store.GrantAsync(roleId, permissionName, cancellationToken);

        return PermissionManagementResult.Success();
    }

    /// <summary>
    /// Revokes a permission from the specified role.
    /// </summary>
    /// <param name="roleId">The identifier of the role.</param>
    /// <param name="permissionName">The name of the permission to revoke.</param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// A result indicating whether the operation succeeded.
    /// </returns>
    public async Task<PermissionManagementResult> RevokeAsync(
        TKey roleId,
        string permissionName,
        CancellationToken cancellationToken = default)
    {
        if (!_catalog.TryGetPermission(permissionName, out _))
        {
            return PermissionManagementResult.Failure(
                PermissionManagementErrorCode.UnknownPermission);
        }

        await _store.RevokeAsync(roleId, permissionName, cancellationToken);

        return PermissionManagementResult.Success();
    }

    /// <summary>
    /// Replaces all permissions currently assigned to the specified role
    /// with the provided set of permissions.
    /// </summary>
    /// <param name="roleId">The identifier of the role.</param>
    /// <param name="permissionNames">
    /// The names of the permissions that should be assigned to the role.
    /// An empty collection removes all permissions from the role.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// A result indicating whether the operation succeeded.
    /// </returns>
    public async Task<PermissionManagementResult> SetPermissionsAsync(
        TKey roleId,
        IReadOnlyCollection<string> permissionNames,
        CancellationToken cancellationToken = default)
    {
        foreach (var permissionName in permissionNames)
        {
            if (!_catalog.TryGetPermission(permissionName, out _))
            {
                return PermissionManagementResult.Failure(
                    PermissionManagementErrorCode.UnknownPermission);
            }
        }

        await _store.SetPermissionsAsync(
            roleId,
            permissionNames,
            cancellationToken);

        return PermissionManagementResult.Success();
    }

    /// <summary>
    /// Gets the permissions assigned directly to the specified role.
    /// </summary>
    /// <param name="roleId">The identifier of the role.</param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// A read-only collection containing the names of the permissions
    /// assigned directly to the role.
    /// </returns>
    public async Task<IReadOnlyCollection<string>> GetPermissionsAsync(
        TKey roleId,
        CancellationToken cancellationToken = default)
    {
        return await _store.GetPermissionsAsync(roleId, cancellationToken);
    }
}