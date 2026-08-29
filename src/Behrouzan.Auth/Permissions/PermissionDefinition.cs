namespace Behrouzan.Auth.Permissions;

/// <summary>
/// Represents an application-defined permission.
/// </summary>
public sealed class PermissionDefinition
{

    /// <summary>
    /// Initializes a new permission definition.
    /// </summary>
    /// <param name="name">
    /// The unique application-defined name of the permission.
    /// </param>
    /// <param name="displayName">
    /// An optional human-readable display name for the permission.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="name"/> is null, empty, or consists only of white-space characters.
    /// </exception>
    public PermissionDefinition(
        string name,
        string? displayName = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        Name = name;
        DisplayName = displayName;
    }

    /// <summary>
    /// Gets the unique application-defined name of the permission.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the optional human-readable display name of the permission.
    /// </summary>
    public string? DisplayName { get; }
}