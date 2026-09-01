namespace Behrouzan.Auth.EntityFrameworkCore.Permissions;

internal sealed class RolePermissionGrant<TKey>
    where TKey : notnull
{
    public TKey RoleId { get; set; } = default!;

    public string PermissionName { get; set; } = string.Empty;
}