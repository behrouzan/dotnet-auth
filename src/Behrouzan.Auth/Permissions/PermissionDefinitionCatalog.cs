using System.Diagnostics.CodeAnalysis;

namespace Behrouzan.Auth.Permissions;

/// <summary>
/// Represents the application permission definitions built from all registered
/// permission definition providers.
/// </summary>
public sealed class PermissionDefinitionCatalog
{
    private readonly IReadOnlyDictionary<
    string,
    PermissionDefinition> _permissions;

    /// <summary>
    /// Initializes a new permission definition catalog.
    /// </summary>
    /// <param name="groups">
    /// The permission groups included in the catalog.
    /// </param>
    public PermissionDefinitionCatalog(
        IReadOnlyList<PermissionGroupDefinition> groups)
    {
        ArgumentNullException.ThrowIfNull(groups);

        Groups = groups.ToArray();

        _permissions =
            Groups
                .SelectMany(group => group.Permissions)
                .ToDictionary(
                    permission => permission.Name,
                    StringComparer.Ordinal);
    }

    /// <summary>
    /// Gets the permission groups included in the catalog.
    /// </summary>
    public IReadOnlyList<PermissionGroupDefinition> Groups { get; }

    /// <summary>
    /// Attempts to find a permission definition by its unique name.
    /// </summary>
    /// <param name="name">
    /// The unique name of the permission to find.
    /// </param>
    /// <param name="permission">
    /// When this method returns <see langword="true"/>, contains the matching
    /// permission definition; otherwise, <see langword="null"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the permission was found; otherwise,
    /// <see langword="false"/>.
    /// </returns>
    public bool TryGetPermission(
        string name,
        [NotNullWhen(true)]
    out PermissionDefinition? permission)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        return _permissions.TryGetValue(
            name,
            out permission);
    }
}