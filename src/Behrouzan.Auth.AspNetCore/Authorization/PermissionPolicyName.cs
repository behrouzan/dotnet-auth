namespace Behrouzan.Auth.AspNetCore.Authorization;

internal static class PermissionPolicyName
{
    private const string SinglePrefix = "Permission:";
    private const string AnyPrefix = "PermissionAny:";
    private const string AllPrefix = "PermissionAll:";
    private const char Separator = '|';

    public static string Create(string permissionName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permissionName);

        return SinglePrefix + Encode(permissionName);
    }

    public static string CreateAny(
        IEnumerable<string> permissionNames)
    {
        return CreateMultiple(
            AnyPrefix,
            permissionNames);
    }

    public static string CreateAll(
        IEnumerable<string> permissionNames)
    {
        return CreateMultiple(
            AllPrefix,
            permissionNames);
    }

    public static bool TryParse(
        string policyName,
        out string permissionName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);

        if (!policyName.StartsWith(
                SinglePrefix,
                StringComparison.Ordinal))
        {
            permissionName = string.Empty;
            return false;
        }

        var encoded =
            policyName[SinglePrefix.Length..];

        if (string.IsNullOrWhiteSpace(encoded))
        {
            permissionName = string.Empty;
            return false;
        }

        permissionName = Decode(encoded);
        return true;
    }

    public static bool TryParseAny(
        string policyName,
        out IReadOnlyList<string> permissionNames)
    {
        return TryParseMultiple(
            policyName,
            AnyPrefix,
            out permissionNames);
    }

    public static bool TryParseAll(
        string policyName,
        out IReadOnlyList<string> permissionNames)
    {
        return TryParseMultiple(
            policyName,
            AllPrefix,
            out permissionNames);
    }

    private static string CreateMultiple(
        string prefix,
        IEnumerable<string> permissionNames)
    {
        ArgumentNullException.ThrowIfNull(permissionNames);

        var names =
            permissionNames
                .ToArray();

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

        return prefix +
            string.Join(
                Separator,
                names
                    .Distinct(StringComparer.Ordinal)
                    .Select(Encode));
    }

    private static bool TryParseMultiple(
        string policyName,
        string prefix,
        out IReadOnlyList<string> permissionNames)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);

        if (!policyName.StartsWith(
                prefix,
                StringComparison.Ordinal))
        {
            permissionNames = [];
            return false;
        }

        var value =
            policyName[prefix.Length..];

        if (string.IsNullOrWhiteSpace(value))
        {
            permissionNames = [];
            return false;
        }

        var encodedNames =
            value.Split(Separator);

        if (encodedNames.Any(
                string.IsNullOrWhiteSpace))
        {
            permissionNames = [];
            return false;
        }

        var names =
            encodedNames
                .Select(Decode)
                .ToArray();

        if (names.Any(
                string.IsNullOrWhiteSpace))
        {
            permissionNames = [];
            return false;
        }

        permissionNames = names;
        return true;
    }
    private static string Encode(string value)
    {
        return Uri.EscapeDataString(value);
    }

    private static string Decode(string value)
    {
        return Uri.UnescapeDataString(value);
    }
}