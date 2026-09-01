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

    public Task<AuthorizationPolicy?>
        GetPolicyAsync(
            string policyName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(
            policyName);

        if (!PermissionPolicyName.TryParse(
                policyName,
                out var permissionName))
        {
            return _fallbackPolicyProvider
                .GetPolicyAsync(policyName);
        }

        var policy =
    new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .AddRequirements(
            new PermissionRequirement(permissionName))
        .Build();

        return Task.FromResult<
            AuthorizationPolicy?>(
                policy);
    }
}