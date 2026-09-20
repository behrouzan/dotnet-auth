using Behrouzan.Auth.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Behrouzan.Auth.AspNetCore.Authentication;

internal sealed class DefaultUserSignInResolver<TUser> : IUserSignInResolver<TUser>
    where TUser : class
{
    private readonly UserManager<TUser> _userManager;
    private readonly IUserIdentifierLookup<TUser>? _identifierLookup;
    private readonly PasswordSignInOptions _options;

    public DefaultUserSignInResolver(
        UserManager<TUser> userManager,
        IOptions<PasswordSignInOptions> options,
        IUserIdentifierLookup<TUser>? identifierLookup = null)
    {
        _userManager = userManager;
        _identifierLookup = identifierLookup;
        _options = options.Value;
    }

    public async Task<UserSignInResolution<TUser>> ResolveAsync(
      string identifier,
      CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);

        var matchingUsers = new List<TUser>();

        if (_options.AllowedIdentifiers.HasFlag(SignInIdentifier.UserName))
        {
            var user = await _userManager.FindByNameAsync(identifier);

            if (user is not null)
            {
                matchingUsers.Add(user);
            }
        }

        if (_options.AllowedIdentifiers.HasFlag(SignInIdentifier.Email))
        {
            var emailUser = await _userManager.FindByEmailAsync(identifier);

            if (emailUser is not null)
            {
                matchingUsers.Add(emailUser);
            }
        }

        if (_options.AllowedIdentifiers.HasFlag(SignInIdentifier.PhoneNumber) &&
            _identifierLookup?.IdentifierType == UserIdentifierType.PhoneNumber)
        {
            matchingUsers.AddRange(
                await _identifierLookup.FindAsync(identifier, cancellationToken));
        }

        TUser? resolvedUser = null;
        string? resolvedUserId = null;

        foreach (var user in matchingUsers)
        {
            var userId = await _userManager.GetUserIdAsync(user);

            if (resolvedUserId is not null &&
                !string.Equals(resolvedUserId, userId, StringComparison.Ordinal))
            {
                return UserSignInResolution<TUser>.Ambiguous();
            }

            resolvedUser = user;
            resolvedUserId = userId;
        }

        return resolvedUser is null
            ? UserSignInResolution<TUser>.NotFound()
            : UserSignInResolution<TUser>.Resolved(resolvedUser);
    }
}
