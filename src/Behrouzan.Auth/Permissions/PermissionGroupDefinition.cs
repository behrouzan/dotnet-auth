namespace Behrouzan.Auth.Permissions;


/// <summary>
/// Represents a group of related application permission definitions.
/// </summary>
public sealed class PermissionGroupDefinition
{
    private readonly List<PermissionDefinition> _permissions = [];
    private readonly Action<string>? _registerPermissionName;

    /// <summary>
    /// Initializes a new permission group definition.
    /// </summary>
    /// <param name="name">
    /// The unique name of the permission group.
    /// </param>
    /// <param name="displayName">
    /// An optional human-readable display name for the group.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="name"/> is null, empty, or consists only of white-space characters.
    /// </exception>
    public PermissionGroupDefinition(
    string name,
    string? displayName = null)
    : this(
        name,
        displayName,
        null)
    {
    }

    internal PermissionGroupDefinition(
        string name,
        string? displayName,
        Action<string>? registerPermissionName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        Name = name;
        DisplayName = displayName;
        _registerPermissionName = registerPermissionName;
    }

    /// <summary>
    /// Gets the unique name of the permission group.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the optional human-readable display name of the permission group.
    /// </summary>
    public string? DisplayName { get; }


    /// <summary>
    /// Gets the permissions defined in this group.
    /// </summary>
    public IReadOnlyList<PermissionDefinition> Permissions =>
        _permissions;

    private bool _isFrozen;

    /// <summary>
    /// Adds a permission definition to this group.
    /// </summary>
    /// <param name="name">
    /// The unique application-defined name of the permission.
    /// </param>
    /// <param name="displayName">
    /// An optional human-readable display name for the permission.
    /// </param>
    /// <returns>
    /// The created permission definition.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="name"/> is null, empty, or consists only of white-space characters.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when a permission with the same name has already been defined.
    /// </exception>
    public PermissionDefinition AddPermission(
        string name,
        string? displayName = null)
    {
        if (_isFrozen)
        {
            throw new InvalidOperationException(
                $"Permission group '{Name}' can no longer be modified.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(name);


        if (_permissions.Any(
    permission =>
        string.Equals(
            permission.Name,
            name,
            StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                $"Permission '{name}' is already defined in group '{Name}'.");
        }

        var permission =
            new PermissionDefinition(
                name,
                displayName);

        _registerPermissionName?.Invoke(name);
        _permissions.Add(permission);

        return permission;
    }

    internal void Freeze()
    {
        _isFrozen = true;
    }
}