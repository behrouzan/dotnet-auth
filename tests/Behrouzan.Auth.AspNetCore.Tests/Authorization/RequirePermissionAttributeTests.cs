using Behrouzan.Auth.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Behrouzan.Auth.AspNetCore.Tests.Authorization;

public sealed class RequirePermissionAttributeTests
{
    [Fact]
    public void Constructor_ShouldSetPermissionName()
    {
        var attribute =
            new RequirePermissionAttribute(
                "Products.Create");

        Assert.Equal(
            "Products.Create",
            attribute.PermissionName);
    }

    [Fact]
    public void Constructor_ShouldCreatePermissionPolicyName()
    {
        var attribute =
            new RequirePermissionAttribute(
                "Products.Create");

        Assert.Equal(
            "Permission:Products.Create",
            attribute.Policy);
    }

    [Fact]
    public async Task Policy_ShouldResolveToPermissionRequirement()
    {
        var attribute =
            new RequirePermissionAttribute(
                "Products.Create");

        var provider =
            new PermissionAuthorizationPolicyProvider(
                Microsoft.Extensions.Options.Options.Create(
                    new Microsoft.AspNetCore.Authorization.AuthorizationOptions()));

        var policy =
            await provider.GetPolicyAsync(
                attribute.Policy!);

        Assert.NotNull(policy);

        var requirement =
            Assert.Single(
                policy.Requirements
                    .OfType<PermissionRequirement>());

        Assert.Equal(
            "Products.Create",
            requirement.PermissionName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_ShouldThrow_WhenPermissionNameIsInvalid(
    string permissionName)
    {
        Assert.Throws<ArgumentException>(
            () => new RequirePermissionAttribute(
                permissionName));
    }

    [Fact]
    public void Constructor_ShouldThrow_WhenPermissionNameIsNull()
    {
        Assert.Throws<ArgumentNullException>(
            () => new RequirePermissionAttribute(
                null!));
    }

    [Fact]
    public void RequireAnyPermission_ShouldCreateAnyPolicy()
    {
        var attribute =
            new RequireAnyPermissionAttribute(
                "Products.Create",
                "Products.Edit");

        Assert.Equal(
            "PermissionAny:Products.Create|Products.Edit",
            attribute.Policy);

        Assert.Equal(
            ["Products.Create", "Products.Edit"],
            attribute.PermissionNames);
    }

    [Fact]
    public void RequireAllPermissions_ShouldCreateAllPolicy()
    {
        var attribute =
            new RequireAllPermissionsAttribute(
                "Products.Edit",
                "Products.View");

        Assert.Equal(
            "PermissionAll:Products.Edit|Products.View",
            attribute.Policy);

        Assert.Equal(
            ["Products.Edit", "Products.View"],
            attribute.PermissionNames);
    }

    [Fact]
    public async Task AnyPolicy_ShouldResolveToAnyPermissionRequirement()
    {
        var provider =
            new PermissionAuthorizationPolicyProvider(
                Options.Create(
                    new AuthorizationOptions()));

        var policy =
            await provider.GetPolicyAsync(
                "PermissionAny:Products.Create|Products.Edit");

        Assert.NotNull(policy);

        var requirement =
            Assert.Single(
                policy.Requirements
                    .OfType<PermissionRequirement>());

        Assert.Equal(
            ["Products.Create", "Products.Edit"],
            requirement.PermissionNames);
    }

    [Fact]
    public async Task AllPolicy_ShouldResolveToAllPermissionRequirement()
    {
        var provider =
            new PermissionAuthorizationPolicyProvider(
                Options.Create(
                    new AuthorizationOptions()));

        var policy =
            await provider.GetPolicyAsync(
                "PermissionAll:Products.Edit|Products.View");

        Assert.NotNull(policy);

        var requirement =
            Assert.Single(
                policy.Requirements
                    .OfType<PermissionRequirement>());

        Assert.Equal(
            ["Products.Edit", "Products.View"],
            requirement.PermissionNames);
    }


}