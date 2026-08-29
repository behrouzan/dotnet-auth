namespace Behrouzan.Auth.Permissions;

internal sealed class PermissionDefinitionManager
{
    private readonly IReadOnlyList<PermissionDefinitionProvider> _providers;

    public PermissionDefinitionManager(
        IEnumerable<PermissionDefinitionProvider> providers)
    {
        ArgumentNullException.ThrowIfNull(providers);

        _providers = providers.ToArray();
    }

    public PermissionDefinitionCatalog Build()
    {
        var context =
            new PermissionDefinitionContext();

        foreach (var provider in _providers)
        {
            provider.Define(context);
        }
        
        foreach (var group in context.Groups)
        {
            group.Freeze();
        }

        return new PermissionDefinitionCatalog(
            context.Groups);
    }
}