using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Behrouzan.Auth.AspNetCore.Authorization;

internal sealed class PermissionAuthorizationPolicyProvider
    : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider
        _fallbackPolicyProvider;

    public PermissionAuthorizationPolicyProvider(
        IOptions<AuthorizationOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _fallbackPolicyProvider =
            new DefaultAuthorizationPolicyProvider(
                options);
    }

    public Task<AuthorizationPolicy>
        GetDefaultPolicyAsync()
    {
        return _fallbackPolicyProvider
            .GetDefaultPolicyAsync();
    }

    public Task<AuthorizationPolicy?>
        GetFallbackPolicyAsync()
    {
        return _fallbackPolicyProvider
            .GetFallbackPolicyAsync();
    }

    public Task<AuthorizationPolicy?> GetPolicyAsync(
        string policyName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            policyName);

        if (PermissionPolicyName.TryParse(
                policyName,
                out var permissionName))
        {
            return Task.FromResult<AuthorizationPolicy?>(
                CreatePolicy(
                    new PermissionRequirement(
                        permissionName)));
        }

        if (PermissionPolicyName.TryParseAny(
                policyName,
                out var anyPermissions))
        {
            return Task.FromResult<AuthorizationPolicy?>(
                CreatePolicy(
                    new PermissionRequirement(
                        anyPermissions,
                        PermissionRequirementMode.Any)));
        }

        if (PermissionPolicyName.TryParseAll(
                policyName,
                out var allPermissions))
        {
            return Task.FromResult<AuthorizationPolicy?>(
                CreatePolicy(
                    new PermissionRequirement(
                        allPermissions,
                        PermissionRequirementMode.All)));
        }

        return _fallbackPolicyProvider
            .GetPolicyAsync(policyName);
    }

    private static AuthorizationPolicy CreatePolicy(
    PermissionRequirement requirement)
    {
        return new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(requirement)
            .Build();
    }

}