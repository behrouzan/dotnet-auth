using Behrouzan.Auth.AspNetCore.Users;
using Behrouzan.Auth.Permissions;
using Microsoft.AspNetCore.Authorization;

namespace Behrouzan.Auth.AspNetCore.Authorization;

internal sealed class PermissionAuthorizationHandler<TKey>
    : AuthorizationHandler<PermissionRequirement>
    where TKey : notnull
{
    private readonly IUserIdResolver<TKey> _userIdResolver;
    private readonly IPermissionChecker<TKey> _permissionChecker;

    public PermissionAuthorizationHandler(
        IUserIdResolver<TKey> userIdResolver,
        IPermissionChecker<TKey> permissionChecker)
    {
        ArgumentNullException.ThrowIfNull(userIdResolver);
        ArgumentNullException.ThrowIfNull(permissionChecker);

        _userIdResolver = userIdResolver;
        _permissionChecker = permissionChecker;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PermissionRequirement requirement)
    {
        if (!_userIdResolver.TryResolve(
                context.User,
                out var userId))
        {
            return;
        }

        var isGranted =
            requirement.Mode switch
            {
                PermissionRequirementMode.Single =>
                    await _permissionChecker.IsGrantedAsync(
                        userId,
                        requirement.PermissionName),

                PermissionRequirementMode.Any =>
                    await _permissionChecker.IsAnyGrantedAsync(
                        userId,
                        requirement.PermissionNames),

                PermissionRequirementMode.All =>
                    await _permissionChecker.AreAllGrantedAsync(
                        userId,
                        requirement.PermissionNames),

                _ =>
                    false
            };

        if (isGranted)
            context.Succeed(requirement);
    }
}