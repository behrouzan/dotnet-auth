using Behrouzan.Auth.Permissions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Behrouzan.Auth.EntityFrameworkCore.Permissions;

internal sealed class EfPermissionGrantStore<
    TContext,
    TUser,
    TRole,
    TKey>
    : IPermissionGrantStore<TKey>
    where TContext : IdentityDbContext<TUser, TRole, TKey>
    where TUser : IdentityUser<TKey>
    where TRole : IdentityRole<TKey>
    where TKey : IEquatable<TKey>
{
    private readonly TContext _dbContext;

    public EfPermissionGrantStore(
        TContext dbContext)
    {
        ArgumentNullException.ThrowIfNull(dbContext);

        _dbContext = dbContext;
    }

    public async Task<IReadOnlyCollection<string>>
        GetGrantedPermissionsAsync(
            TKey userId,
            CancellationToken cancellationToken = default)
    {
        var roleIds =
            _dbContext.UserRoles
                .Where(userRole =>
                    userRole.UserId.Equals(userId))
                .Select(userRole =>
                    userRole.RoleId);

        return await _dbContext
            .Set<RolePermissionGrant<TKey>>()
            .Where(grant =>
                roleIds.Contains(grant.RoleId))
            .Select(grant =>
                grant.PermissionName)
            .Distinct()
            .ToArrayAsync(cancellationToken);
    }
}