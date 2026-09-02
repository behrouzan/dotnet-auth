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

        if (!_catalog.TryGetPermission(permissionName, out _))
            return false;

        var grantedPermissions =
            await _grantStore.GetGrantedPermissionsAsync(
                userId,
                cancellationToken);

        return grantedPermissions.Contains(
            permissionName,
            StringComparer.Ordinal);
    }

    public async Task<bool> IsAnyGrantedAsync(
        TKey userId,
        IEnumerable<string> permissionNames,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);

        var requestedPermissions =
            GetValidatedPermissionNames(permissionNames);

        var definedPermissions =
            requestedPermissions
                .Where(permissionName =>
                    _catalog.TryGetPermission(
                        permissionName,
                        out _))
                .ToArray();

        if (definedPermissions.Length == 0)
            return false;

        var grantedPermissions =
            await _grantStore.GetGrantedPermissionsAsync(
                userId,
                cancellationToken);

        var grantedSet =
            grantedPermissions.ToHashSet(
                StringComparer.Ordinal);

        return definedPermissions.Any(
            grantedSet.Contains);
    }

    public async Task<bool> AreAllGrantedAsync(
        TKey userId,
        IEnumerable<string> permissionNames,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(userId);

        var requestedPermissions =
            GetValidatedPermissionNames(permissionNames);

        foreach (var permissionName in requestedPermissions)
        {
            if (!_catalog.TryGetPermission(
                    permissionName,
                    out _))
            {
                return false;
            }
        }

        var grantedPermissions =
            await _grantStore.GetGrantedPermissionsAsync(
                userId,
                cancellationToken);

        var grantedSet =
            grantedPermissions.ToHashSet(
                StringComparer.Ordinal);

        return requestedPermissions.All(
            grantedSet.Contains);
    }

    private static string[] GetValidatedPermissionNames(
        IEnumerable<string> permissionNames)
    {
        ArgumentNullException.ThrowIfNull(
            permissionNames);

        var names =
            permissionNames.ToArray();

        if (names.Length == 0)
        {
            throw new ArgumentException(
                "At least one permission name must be provided.",
                nameof(permissionNames));
        }

        foreach (var permissionName in names)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(
                permissionName);
        }

        return names
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }
}