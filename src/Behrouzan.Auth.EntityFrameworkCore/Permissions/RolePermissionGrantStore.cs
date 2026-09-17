using Behrouzan.Auth.Permissions;
using Microsoft.EntityFrameworkCore;

namespace Behrouzan.Auth.EntityFrameworkCore.Permissions;


internal sealed class RolePermissionGrantStore<TContext, TKey>
    : IRolePermissionGrantStore<TKey>
    where TContext : DbContext
    where TKey : notnull
{
    private readonly TContext _dbContext;

    public RolePermissionGrantStore(TContext dbContext)
    {
        ArgumentNullException.ThrowIfNull(dbContext);

        _dbContext = dbContext;
    }

    public async Task<IReadOnlyCollection<string>> GetPermissionsAsync(
        TKey roleId,
        CancellationToken cancellationToken = default)
    {
        return await _dbContext
            .Set<RolePermissionGrant<TKey>>()
            .Where(grant => grant.RoleId.Equals(roleId))
            .Select(grant => grant.PermissionName)
            .ToListAsync(cancellationToken);
    }

    public async Task GrantAsync(
        TKey roleId,
        string permissionName,
        CancellationToken cancellationToken = default)
    {
        var exists = await _dbContext
            .Set<RolePermissionGrant<TKey>>()
            .AnyAsync(
                grant => grant.RoleId.Equals(roleId) &&
                     grant.PermissionName == permissionName,
                cancellationToken);

        if (exists)
        {
            return;
        }

        await _dbContext
            .Set<RolePermissionGrant<TKey>>()
            .AddAsync(
                new RolePermissionGrant<TKey>
                {
                    RoleId = roleId,
                    PermissionName = permissionName
                },
                cancellationToken);

        await _dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task RevokeAsync(
        TKey roleId,
        string permissionName,
        CancellationToken cancellationToken = default)
    {
        await _dbContext
            .Set<RolePermissionGrant<TKey>>()
            .Where(grant =>
                grant.RoleId.Equals(roleId) &&
                grant.PermissionName == permissionName)
            .ExecuteDeleteAsync(cancellationToken);
    }

    public async Task SetPermissionsAsync(
        TKey roleId,
        IReadOnlyCollection<string> permissionNames,
        CancellationToken cancellationToken = default)
    {
        await using var transaction =
        await _dbContext.Database.BeginTransactionAsync(cancellationToken);

        try
        {
            var oldGrants = await _dbContext
                   .Set<RolePermissionGrant<TKey>>()
                   .Where(grant => grant.RoleId.Equals(roleId))
                   .Select(grant => grant.PermissionName)
                   .ToListAsync(cancellationToken);

            var toAdd = permissionNames
                .Except(oldGrants, StringComparer.Ordinal)
                .ToArray();

            var toRemove = oldGrants
                .Except(permissionNames, StringComparer.Ordinal)
                .ToArray();

            if (toRemove.Length > 0)
            {
                await _dbContext.Set<RolePermissionGrant<TKey>>()
                    .Where(grant => grant.RoleId.Equals(roleId) && toRemove.Contains(grant.PermissionName))
                    .ExecuteDeleteAsync(cancellationToken);
            }

            if (toAdd.Length > 0)
            {
                var grantsToAdd = toAdd
                    .Select(permissionName => new RolePermissionGrant<TKey>
                    {
                        RoleId = roleId,
                        PermissionName = permissionName
                    })
                    .ToArray();

                await _dbContext
                    .Set<RolePermissionGrant<TKey>>()
                    .AddRangeAsync(grantsToAdd, cancellationToken);

                await _dbContext.SaveChangesAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None);
            throw;
        }
    }
}