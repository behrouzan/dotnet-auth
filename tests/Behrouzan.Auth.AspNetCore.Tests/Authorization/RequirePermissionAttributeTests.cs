using Behrouzan.Auth.AspNetCore.Authorization;

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
}