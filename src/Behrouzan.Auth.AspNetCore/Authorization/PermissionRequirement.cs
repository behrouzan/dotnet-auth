using Microsoft.AspNetCore.Authorization;

namespace Behrouzan.Auth.AspNetCore.Authorization;

/// <summary>
/// Represents an authorization requirement based on one or more permissions.
/// </summary>
internal sealed class PermissionRequirement
    : IAuthorizationRequirement
{
    /// <summary>
    /// Initializes a new instance of the
    /// <see cref="PermissionRequirement"/> class.
    /// </summary>
    /// <param name="permissionName">
    /// The name of the required permission.
    /// </param>
    public PermissionRequirement(
        string permissionName)
        : this(
            [permissionName],
            PermissionRequirementMode.Single)
    {
    }

    internal PermissionRequirement(
        IReadOnlyCollection<string> permissionNames,
        PermissionRequirementMode mode)
    {
        ArgumentNullException.ThrowIfNull(permissionNames);

        if (permissionNames.Count == 0)
        {
            throw new ArgumentException(
                "At least one permission name must be provided.",
                nameof(permissionNames));
        }

        foreach (var permissionName in permissionNames)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(
                permissionName);
        }

        PermissionNames =
            permissionNames
                .Distinct(StringComparer.Ordinal)
                .ToArray();

        Mode = mode;
    }

    /// <summary>
    /// Gets the permission names associated with this requirement.
    /// </summary>
    public IReadOnlyCollection<string> PermissionNames { get; }

    /// <summary>
    /// Gets the permission name when this requirement represents
    /// a single permission.
    /// </summary>
    public string PermissionName =>
        PermissionNames.Single();

    internal PermissionRequirementMode Mode { get; }
}