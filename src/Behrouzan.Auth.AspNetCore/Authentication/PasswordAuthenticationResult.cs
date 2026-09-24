namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Represents the result of a password authentication attempt.
/// </summary>
/// <typeparam name="TUser">The application user type.</typeparam>
public sealed class PasswordAuthenticationResult<TUser>
    where TUser : class
{
    private PasswordAuthenticationResult(
        TUser? user,
        PasswordAuthenticationErrorCode? errorCode)
    {
        User = user;
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Gets a value indicating whether authentication succeeded.
    /// </summary>
    public bool IsSuccess => User is not null;

    /// <summary>
    /// Gets the authenticated user when authentication succeeds.
    /// </summary>
    public TUser? User { get; }

    /// <summary>
    /// Gets the error code when authentication fails.
    /// </summary>
    public PasswordAuthenticationErrorCode? ErrorCode { get; }

    /// <summary>
    /// Creates a successful password authentication result.
    /// </summary>
    /// <param name="user">The authenticated user.</param>
    /// <returns>A successful authentication result.</returns>
    public static PasswordAuthenticationResult<TUser> Success(TUser user)
    {
        ArgumentNullException.ThrowIfNull(user);

        return new(user, null);
    }

    /// <summary>
    /// Creates a failed password authentication result.
    /// </summary>
    /// <param name="errorCode">The error that caused authentication to fail.</param>
    /// <returns>A failed authentication result.</returns>
    public static PasswordAuthenticationResult<TUser> Failure(
        PasswordAuthenticationErrorCode errorCode)
    {
        return new(null, errorCode);
    }
}
