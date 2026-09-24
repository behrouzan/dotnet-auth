using Microsoft.AspNetCore.Identity;

namespace Behrouzan.Auth.AspNetCore.Authentication;

internal sealed class DefaultTokenUserIdentityResolver<TUser, TKey>
    : ITokenUserIdentityResolver<TUser, TKey>
    where TUser : IdentityUser<TKey>
    where TKey : notnull, IEquatable<TKey>
{
    private readonly UserManager<TUser> _userManager;

    public DefaultTokenUserIdentityResolver(UserManager<TUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<TokenUserIdentity<TKey>> ResolveAsync(
        TUser user,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        var subject = await _userManager.GetUserIdAsync(user);

        return new TokenUserIdentity<TKey>(user.Id, subject);
    }
}
