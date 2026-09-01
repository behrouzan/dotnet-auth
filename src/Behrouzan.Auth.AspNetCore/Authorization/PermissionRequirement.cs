using Microsoft.AspNetCore.Authorization;

namespace Behrouzan.Auth.AspNetCore.Authorization;

/// <summary>
/// Represents an authorization requirement that requires
/// a specific permission.
/// </summary>
public sealed class PermissionRequirement
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
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            permissionName);

        PermissionName = permissionName;
    }

    /// <summary>
    /// Gets the name of the required permission.
    /// </summary>
    public string PermissionName { get; }
}