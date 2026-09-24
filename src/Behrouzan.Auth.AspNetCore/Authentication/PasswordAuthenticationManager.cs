using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Authenticates a user by identifier and password without signing the user in.
/// </summary>
/// <typeparam name="TUser">The application user type.</typeparam>
public sealed class PasswordAuthenticationManager<TUser>
    where TUser : class
{
    private readonly IUserSignInResolver<TUser> _userResolver;
    private readonly SignInManager<TUser> _signInManager;
    private readonly PasswordSignInOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordAuthenticationManager{TUser}"/> class.
    /// </summary>
    /// <param name="userResolver">The service used to resolve sign-in identifiers.</param>
    /// <param name="signInManager">The ASP.NET Core Identity sign-in manager.</param>
    /// <param name="options">The configured password sign-in options.</param>
    public PasswordAuthenticationManager(
        IUserSignInResolver<TUser> userResolver,
        SignInManager<TUser> signInManager,
        IOptions<PasswordSignInOptions> options)
    {
        _userResolver = userResolver;
        _signInManager = signInManager;
        _options = options.Value;
    }

    /// <summary>
    /// Authenticates a user using an identifier and password without issuing a sign-in cookie.
    /// </summary>
    /// <param name="identifier">The identifier used to locate the user.</param>
    /// <param name="password">The user's password.</param>
    /// <param name="cancellationToken">A token that can be used to cancel identifier resolution.</param>
    /// <returns>The authenticated user or the reason authentication failed.</returns>
    public async Task<PasswordAuthenticationResult<TUser>> AuthenticateAsync(
        string identifier,
        string password,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        var resolution = await _userResolver.ResolveAsync(identifier, cancellationToken);

        if (resolution.Status != UserSignInResolutionStatus.Resolved || resolution.User is null)
        {
            return PasswordAuthenticationResult<TUser>.Failure(
                PasswordAuthenticationErrorCode.InvalidCredentials);
        }

        var identityResult = await _signInManager.CheckPasswordSignInAsync(
            resolution.User,
            password,
            _options.LockoutOnFailure);

        if (identityResult.Succeeded)
        {
            return PasswordAuthenticationResult<TUser>.Success(resolution.User);
        }

        if (identityResult.IsLockedOut)
        {
            return PasswordAuthenticationResult<TUser>.Failure(
                PasswordAuthenticationErrorCode.LockedOut);
        }

        if (identityResult.IsNotAllowed)
        {
            return PasswordAuthenticationResult<TUser>.Failure(
                PasswordAuthenticationErrorCode.NotAllowed);
        }

        return PasswordAuthenticationResult<TUser>.Failure(
            PasswordAuthenticationErrorCode.InvalidCredentials);
    }
}
