namespace Behrouzan.Auth.Permissions;

internal sealed class PermissionChecker<TKey>
    : IPermissionChecker<TKey>
    where TKey : notnull
{
    private readonly PermissionDefinitionCatalog _catalog;
    private readonly IPermissionGrantStore<TKey> _grantStore;

    public PermissionChecker(
        PermissionDefinitionCatalog catalog,
        IPermissionGrantStore<TKey> grantStore)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(grantStore);

        _catalog = catalog;
        _grantStore = grantStore;
    }

    public async Task<bool> IsGrantedAsync(
        TKey userId,
        string permissionName,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentException.ThrowIfNullOrWhiteSpace(permissionName);

        if (!_catalog.TryGetPermission(
            permissionName,
            out _))
        {
            return false;
        }

        var grantedPermissions =
            await _grantStore.GetGrantedPermissionsAsync(
                userId,
                cancellationToken);

        return grantedPermissions.Contains(
            permissionName,
            StringComparer.Ordinal);
    }
}