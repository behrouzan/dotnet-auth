using System.Security.Claims;
using Behrouzan.Auth.AspNetCore.Users;

namespace Behrouzan.Auth.AspNetCore.Tests.Users;

public sealed class DefaultUserIdResolverTests
{
    [Fact]
    public void TryResolve_ShouldResolveGuidUserId()
    {
        var expectedUserId = Guid.NewGuid();

        var principal =
            CreatePrincipal(expectedUserId.ToString());

        var resolver =
            new DefaultUserIdResolver<Guid>();

        var result =
            resolver.TryResolve(
                principal,
                out var userId);

        Assert.True(result);
        Assert.Equal(expectedUserId, userId);
    }

    [Fact]
    public void TryResolve_ShouldResolveIntUserId()
    {
        var principal =
            CreatePrincipal("123");

        var resolver =
            new DefaultUserIdResolver<int>();

        var result =
            resolver.TryResolve(
                principal,
                out var userId);

        Assert.True(result);
        Assert.Equal(123, userId);
    }

    [Fact]
    public void TryResolve_ShouldReturnFalse_WhenClaimIsMissing()
    {
        var principal =
            new ClaimsPrincipal(
                new ClaimsIdentity());

        var resolver =
            new DefaultUserIdResolver<Guid>();

        var result =
            resolver.TryResolve(
                principal,
                out _);

        Assert.False(result);
    }

    [Fact]
    public void TryResolve_ShouldReturnFalse_WhenClaimIsInvalid()
    {
        var principal =
            CreatePrincipal("not-a-guid");

        var resolver =
            new DefaultUserIdResolver<Guid>();

        var result =
            resolver.TryResolve(
                principal,
                out _);

        Assert.False(result);
    }

    private static ClaimsPrincipal CreatePrincipal(
        string userId)
    {
        var identity =
            new ClaimsIdentity(
                [
                    new Claim(
                        ClaimTypes.NameIdentifier,
                        userId)
                ]);

        return new ClaimsPrincipal(identity);
    }
}