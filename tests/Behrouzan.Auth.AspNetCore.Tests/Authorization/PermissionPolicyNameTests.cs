using Behrouzan.Auth.AspNetCore.Authorization;

namespace Behrouzan.Auth.AspNetCore.Tests.Authorization;

public sealed class PermissionPolicyNameTests
{
    [Fact]
    public void Any_ShouldRoundTripPermissionNames()
    {
        var policyName =
            PermissionPolicyName.CreateAny(
            [
                "Products.Create",
                "Products.Special|Edit",
                "Products.50%Off"
            ]);

        var result =
            PermissionPolicyName.TryParseAny(
                policyName,
                out var permissionNames);

        Assert.True(result);

        Assert.Equal(
            [
                "Products.Create",
                "Products.Special|Edit",
                "Products.50%Off"
            ],
            permissionNames);
    }

    [Fact]
    public void All_ShouldRoundTripPermissionNames()
    {
        var policyName =
            PermissionPolicyName.CreateAll(
            [
                "Products.Edit",
                "Orders.Approve"
            ]);

        var result =
            PermissionPolicyName.TryParseAll(
                policyName,
                out var permissionNames);

        Assert.True(result);

        Assert.Equal(
            [
                "Products.Edit",
                "Orders.Approve"
            ],
            permissionNames);
    }

    [Fact]
    public void Any_ShouldRejectEmptyPermissionSegment()
    {
        var result =
            PermissionPolicyName.TryParseAny(
            "PermissionAny:Products.Create||Products.Edit",
            out var permissionNames);

        Assert.False(result);
        Assert.Empty(permissionNames);
    }
}