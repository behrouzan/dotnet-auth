using Microsoft.AspNetCore.Authorization;

namespace Behrouzan.Auth.AspNetCore.Authorization;

/// <summary>
/// Specifies that access to the decorated resource requires
/// at least one of the specified permissions.
/// </summary>
[AttributeUsage(
    AttributeTargets.Class | AttributeTargets.Method,
    AllowMultiple = true,
    Inherited = true)]
public sealed class RequireAnyPermissionAttribute
    : AuthorizeAttribute
{
    /// <summary>
    /// Initializes a new instance of the
    /// <see cref="RequireAnyPermissionAttribute"/> class.
    /// </summary>
    /// <param name="permissionNames">
    /// The permission names, at least one of which is required.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="permissionNames"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when no permission names are provided or when any
    /// permission name is null, empty, or consists only of white-space
    /// characters.
    /// </exception>
    public RequireAnyPermissionAttribute(
        params string[] permissionNames)
    {
        ArgumentNullException.ThrowIfNull(permissionNames);

        PermissionNames =
            permissionNames
                .Distinct(StringComparer.Ordinal)
                .ToArray();

        Policy =
            PermissionPolicyName.CreateAny(
                PermissionNames);
    }

    /// <summary>
    /// Gets the permission names associated with this attribute.
    /// </summary>
    public IReadOnlyCollection<string> PermissionNames { get; }
}