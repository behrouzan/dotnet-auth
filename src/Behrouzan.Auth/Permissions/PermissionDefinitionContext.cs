namespace Behrouzan.Auth.Permissions;



internal sealed class PermissionDefinitionContext
    : IPermissionDefinitionContext
{
    private readonly HashSet<string> _permissionNames =
    new(StringComparer.Ordinal);

    private readonly List<PermissionGroupDefinition> _groups = [];

    public IReadOnlyList<PermissionGroupDefinition> Groups =>
        _groups;

    public PermissionGroupDefinition AddGroup(
        string name,
        string? displayName = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        if (_groups.Any(
            group =>
                string.Equals(
                    group.Name,
                    name,
                    StringComparison.Ordinal)))
        {
            throw new InvalidOperationException(
                $"Permission group '{name}' is already defined.");
        }


        var group =
    new PermissionGroupDefinition(
        name,
        displayName,
        RegisterPermissionName);

        _groups.Add(group);

        return group;
    }

    private void RegisterPermissionName(
    string name)
    {
        if (!_permissionNames.Add(name))
        {
            throw new InvalidOperationException(
                $"Permission '{name}' is already defined.");
        }
    }
}