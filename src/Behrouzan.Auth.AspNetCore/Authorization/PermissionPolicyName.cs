namespace Behrouzan.Auth.AspNetCore.Authorization;

internal static class PermissionPolicyName
{
    private const string Prefix = "Permission:";

    public static string Create(
        string permissionName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            permissionName);

        return Prefix + permissionName;
    }

    public static bool TryParse(
        string policyName,
        out string permissionName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            policyName);

        if (!policyName.StartsWith(
                Prefix,
                StringComparison.Ordinal))
        {
            permissionName = string.Empty;
            return false;
        }

        permissionName =
            policyName[Prefix.Length..];

        if (string.IsNullOrWhiteSpace(
                permissionName))
        {
            permissionName = string.Empty;
            return false;
        }

        return true;
    }
}