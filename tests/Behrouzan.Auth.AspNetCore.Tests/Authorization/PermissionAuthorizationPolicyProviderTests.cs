using Behrouzan.Auth.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace Behrouzan.Auth.AspNetCore.Tests.Authorization;

public sealed class PermissionAuthorizationPolicyProviderTests
{
    [Fact]
    public async Task GetPolicyAsync_ShouldCreatePolicy_ForPermissionPolicy()
    {
        var provider =
            CreateProvider();

        var policy =
            await provider.GetPolicyAsync(
                "Permission:Products.Create");

        Assert.NotNull(policy);

        var requirement =
            Assert.Single(
                policy.Requirements
                    .OfType<PermissionRequirement>());

        Assert.Equal(
            "Products.Create",
            requirement.PermissionName);
    }

    [Fact]
    public async Task GetPolicyAsync_ShouldUseFallbackProvider_ForRegularPolicy()
    {
        var options =
            new AuthorizationOptions();

        options.AddPolicy(
            "AdminOnly",
            policy =>
                policy.RequireRole("Admin"));

        var provider =
            new PermissionAuthorizationPolicyProvider(
                Options.Create(options));

        var policy =
            await provider.GetPolicyAsync(
                "AdminOnly");

        Assert.NotNull(policy);

        var roleRequirement =
            Assert.Single(
                policy.Requirements
                    .OfType<RolesAuthorizationRequirement>());

        Assert.Contains(
            "Admin",
            roleRequirement.AllowedRoles);
    }

    [Fact]
    public async Task GetPolicyAsync_ShouldReturnNull_ForUnknownRegularPolicy()
    {
        var provider =
            CreateProvider();

        var policy =
            await provider.GetPolicyAsync(
                "SomethingUnknown");

        Assert.Null(policy);
    }

    [Fact]
    public async Task GetPolicyAsync_ShouldRequireAuthenticatedUser_ForPermissionPolicy()
    {
        var options =
            Options.Create(
                new AuthorizationOptions());

        var provider =
            new PermissionAuthorizationPolicyProvider(
                options);

        var policy =
            await provider.GetPolicyAsync(
                "Permission:Products.Create");

        Assert.NotNull(policy);

        Assert.Contains(
            policy.Requirements,
            requirement =>
                requirement is
                    DenyAnonymousAuthorizationRequirement);
    }

    private static PermissionAuthorizationPolicyProvider
        CreateProvider()
    {
        return new PermissionAuthorizationPolicyProvider(
            Options.Create(
                new AuthorizationOptions()));
    }
}