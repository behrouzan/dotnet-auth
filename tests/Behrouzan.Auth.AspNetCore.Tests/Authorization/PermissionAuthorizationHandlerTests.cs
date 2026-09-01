using System.Security.Claims;
using Behrouzan.Auth.AspNetCore.Authorization;
using Behrouzan.Auth.AspNetCore.Users;
using Behrouzan.Auth.Permissions;
using Microsoft.AspNetCore.Authorization;

namespace Behrouzan.Auth.AspNetCore.Tests.Authorization;

public sealed class PermissionAuthorizationHandlerTests
{
    [Fact]
    public async Task HandleAsync_ShouldSucceed_WhenPermissionIsGranted()
    {
        var userId = Guid.NewGuid();

        var userIdResolver =
            new FakeUserIdResolver<Guid>(
                userId,
                true);

        var permissionChecker =
            new FakePermissionChecker<Guid>(
                true);

        var handler =
            new PermissionAuthorizationHandler<Guid>(
                userIdResolver,
                permissionChecker);

        var requirement =
            new PermissionRequirement(
                "Products.Create");

        var context =
            CreateContext(requirement);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);

        Assert.Equal(
            userId,
            permissionChecker.ReceivedUserId);

        Assert.Equal(
            "Products.Create",
            permissionChecker.ReceivedPermissionName);
    }

    [Fact]
    public async Task HandleAsync_ShouldNotSucceed_WhenPermissionIsNotGranted()
    {
        var userIdResolver =
            new FakeUserIdResolver<Guid>(
                Guid.NewGuid(),
                true);

        var permissionChecker =
            new FakePermissionChecker<Guid>(
                false);

        var handler =
            new PermissionAuthorizationHandler<Guid>(
                userIdResolver,
                permissionChecker);

        var requirement =
            new PermissionRequirement(
                "Products.Create");

        var context =
            CreateContext(requirement);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
        Assert.False(context.HasFailed);
    }

    [Fact]
    public async Task HandleAsync_ShouldNotCallPermissionChecker_WhenUserIdCannotBeResolved()
    {
        var userIdResolver =
            new FakeUserIdResolver<Guid>(
                default,
                false);

        var permissionChecker =
            new FakePermissionChecker<Guid>(
                true);

        var handler =
            new PermissionAuthorizationHandler<Guid>(
                userIdResolver,
                permissionChecker);

        var requirement =
            new PermissionRequirement(
                "Products.Create");

        var context =
            CreateContext(requirement);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
        Assert.Equal(
            0,
            permissionChecker.CallCount);
    }

    private static AuthorizationHandlerContext
        CreateContext(
            PermissionRequirement requirement)
    {
        var user =
            new ClaimsPrincipal(
                new ClaimsIdentity());

        return new AuthorizationHandlerContext(
            [requirement],
            user,
            resource: null);
    }

    private sealed class FakeUserIdResolver<TKey>
        : IUserIdResolver<TKey>
        where TKey : notnull
    {
        private readonly TKey _userId;
        private readonly bool _result;

        public FakeUserIdResolver(
            TKey userId,
            bool result)
        {
            _userId = userId;
            _result = result;
        }

        public bool TryResolve(
            ClaimsPrincipal principal,
            out TKey userId)
        {
            userId = _userId;
            return _result;
        }
    }

    private sealed class FakePermissionChecker<TKey>
        : IPermissionChecker<TKey>
        where TKey : notnull
    {
        private readonly bool _result;

        public FakePermissionChecker(
            bool result)
        {
            _result = result;
        }

        public int CallCount { get; private set; }

        public TKey? ReceivedUserId { get; private set; }

        public string? ReceivedPermissionName { get; private set; }

        public Task<bool> IsGrantedAsync(
            TKey userId,
            string permissionName,
            CancellationToken cancellationToken = default)
        {
            CallCount++;

            ReceivedUserId = userId;
            ReceivedPermissionName = permissionName;

            return Task.FromResult(_result);
        }
    }
}