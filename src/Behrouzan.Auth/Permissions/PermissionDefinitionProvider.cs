namespace Behrouzan.Auth.Permissions;


/// <summary>
/// Provides application-defined permission groups and permissions.
/// </summary>
public abstract class PermissionDefinitionProvider
{
    /// <summary>
    /// Defines the permission groups and permissions provided by this provider.
    /// </summary>
    /// <param name="context">
    /// The permission definition context used to register definitions.
    /// </param>
    public abstract void Define(
        IPermissionDefinitionContext context);
}