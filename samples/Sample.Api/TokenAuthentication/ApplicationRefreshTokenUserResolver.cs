using Behrouzan.Auth.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Sample.Api.Data;
using Sample.Api.Identity;

namespace Sample.Api.TokenAuthentication;

internal sealed class ApplicationRefreshTokenUserResolver
    : IRefreshTokenUserResolver<ApplicationUser, Guid>
{
    private readonly ApplicationDbContext _dbContext;

    public ApplicationRefreshTokenUserResolver(
        ApplicationDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public Task<ApplicationUser?> ResolveAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        return _dbContext.Users.SingleOrDefaultAsync(
            user => user.Id == userId,
            cancellationToken);
    }
}
