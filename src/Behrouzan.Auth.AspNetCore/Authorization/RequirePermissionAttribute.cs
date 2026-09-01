using Microsoft.AspNetCore.Authorization;

namespace Behrouzan.Auth.AspNetCore.Authorization;

/// <summary>
/// Specifies that access to the decorated resource requires
/// the specified permission.
/// </summary>
[AttributeUsage(
    AttributeTargets.Class | AttributeTargets.Method,
    AllowMultiple = true,
    Inherited = true)]
public sealed class RequirePermissionAttribute
    : AuthorizeAttribute
{
    /// <summary>
    /// Initializes a new instance of the
    /// <see cref="RequirePermissionAttribute"/> class.
    /// </summary>
    /// <param name="permissionName">
    /// The name of the permission required to access the resource.
    /// </param>
    public RequirePermissionAttribute(
        string permissionName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            permissionName);

        PermissionName = permissionName;
        Policy = PermissionPolicyName.Create(permissionName);
    }

    /// <summary>
    /// Gets the name of the required permission.
    /// </summary>
    public string PermissionName { get; }
}