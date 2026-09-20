namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Provides configuration for password-based sign-in.
/// </summary>
public sealed class PasswordSignInOptions
{
    /// <summary>
    /// Gets or sets the built-in identifiers that may be used
    /// to locate a user during password sign-in.
    /// </summary>
    public SignInIdentifier AllowedIdentifiers { get; set; }
        = SignInIdentifier.UserName;


    /// <summary>
    /// Gets or sets a value indicating whether failed password sign-in
    /// attempts should count toward account lockout.
    /// </summary>
    public bool LockoutOnFailure { get; set; } = true;
}