namespace Behrouzan.Auth.Permissions;

/// <summary>
/// Represents the application permission definitions built from all registered
/// permission definition providers.
/// </summary>
public sealed class PermissionDefinitionCatalog
{
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
    }

    /// <summary>
    /// Gets the permission groups included in the catalog.
    /// </summary>
    public IReadOnlyList<PermissionGroupDefinition> Groups { get; }
}