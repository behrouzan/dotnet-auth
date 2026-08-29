namespace Behrouzan.Auth.Permissions;

/// <summary>
/// Defines the context used by permission providers to register application permission definitions.
/// </summary>
public interface IPermissionDefinitionContext
{

    /// <summary>
    /// Adds a permission group to the application permission catalog.
    /// </summary>
    /// <param name="name">
    /// The unique name of the permission group.
    /// </param>
    /// <param name="displayName">
    /// An optional human-readable display name for the group.
    /// </param>
    /// <returns>
    /// The created permission group definition.
    /// </returns>
    PermissionGroupDefinition AddGroup(
        string name,
        string? displayName = null);
}