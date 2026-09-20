namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Represents the result of a password sign-in attempt.
/// </summary>
public sealed class PasswordSignInResult
{
    private PasswordSignInResult(
        bool isSuccess,
        PasswordSignInErrorCode? errorCode)
    {
        IsSuccess = isSuccess;
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Gets a value indicating whether the sign-in succeeded.
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// Gets the error code when the sign-in failed.
    /// </summary>
    public PasswordSignInErrorCode? ErrorCode { get; }

    /// <summary>
    /// Creates a successful sign-in result.
    /// </summary>
    public static PasswordSignInResult Success()
    {
        return new PasswordSignInResult(true, null);
    }

    /// <summary>
    /// Creates a failed sign-in result.
    /// </summary>
    public static PasswordSignInResult Failure(
        PasswordSignInErrorCode errorCode)
    {
        return new PasswordSignInResult(false, errorCode);
    }
}