using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Coordinates password-based sign-in using a configurable user resolver
/// and ASP.NET Core Identity.
/// </summary>
/// <typeparam name="TUser">The application user type.</typeparam>
public sealed class PasswordSignInManager<TUser>
    where TUser : class
{
    private readonly IUserSignInResolver<TUser> _userResolver;
    private readonly SignInManager<TUser> _signInManager;
    private readonly PasswordSignInOptions _options;

    /// <summary>
    /// Initializes a password sign-in coordinator.
    /// </summary>
    /// <param name="userResolver">The resolver used to find a user by identifier.</param>
    /// <param name="signInManager">The ASP.NET Core Identity sign-in manager.</param>
    /// <param name="options">The configured password sign-in options.</param>
    public PasswordSignInManager(
        IUserSignInResolver<TUser> userResolver,
        SignInManager<TUser> signInManager,
        IOptions<PasswordSignInOptions> options)
    {
        _userResolver = userResolver;
        _signInManager = signInManager;
        _options = options.Value;
    }

    /// <summary>
    /// Attempts to sign in a user using an identifier and password.
    /// </summary>
    public async Task<PasswordSignInResult> SignInAsync(
        string identifier,
        string password,
        bool isPersistent = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        var resolution = await _userResolver.ResolveAsync(
            identifier,
            cancellationToken);

        if (resolution.Status != UserSignInResolutionStatus.Resolved ||
            resolution.User is null)
        {
            return PasswordSignInResult.Failure(
                PasswordSignInErrorCode.InvalidCredentials);
        }

        var identityResult = await _signInManager.PasswordSignInAsync(
            resolution.User,
            password,
            isPersistent,
            _options.LockoutOnFailure);

        if (identityResult.Succeeded)
        {
            return PasswordSignInResult.Success();
        }

        if (identityResult.IsLockedOut)
        {
            return PasswordSignInResult.Failure(
                PasswordSignInErrorCode.LockedOut);
        }

        if (identityResult.RequiresTwoFactor)
        {
            return PasswordSignInResult.Failure(
                PasswordSignInErrorCode.RequiresTwoFactor);
        }

        if (identityResult.IsNotAllowed)
        {
            return PasswordSignInResult.Failure(
                PasswordSignInErrorCode.NotAllowed);
        }

        return PasswordSignInResult.Failure(
            PasswordSignInErrorCode.InvalidCredentials);
    }
}
