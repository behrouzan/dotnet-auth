using Behrouzan.Auth.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Behrouzan.Auth.EntityFrameworkCore.Authentication;

internal sealed class PhoneNumberUserIdentifierLookup<TContext, TUser, TKey>
    : IUserIdentifierLookup<TUser>
    where TContext : DbContext
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey>
{
    private readonly TContext _dbContext;

    public PhoneNumberUserIdentifierLookup(TContext dbContext)
    {
        ArgumentNullException.ThrowIfNull(dbContext);
        _dbContext = dbContext;
    }

    /// <inheritdoc />
    public UserIdentifierType IdentifierType => UserIdentifierType.PhoneNumber;

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<TUser>> FindAsync(
        string identifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        return await _dbContext
            .Set<TUser>()
            .Where(user => user.PhoneNumber == identifier)
            .ToArrayAsync(cancellationToken);
    }
}
