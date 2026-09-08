namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Represents the result of a refresh token operation.
/// </summary>
public sealed class RefreshTokenResult
{
    /// <summary>
    /// Gets a value indicating whether the refresh token operation succeeded.
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// Gets the newly issued refresh token when the operation succeeds;
    /// otherwise, <see langword="null"/>.
    /// </summary>
    public string? Token { get; }

    /// <summary>
    /// Gets the error code when the operation fails;
    /// otherwise, <see langword="null"/>.
    /// </summary>
    public string? ErrorCode { get; }

    private RefreshTokenResult(bool succeeded, string data)
    {
        IsSuccess = succeeded;

        if (succeeded)
        {
            Token = data;
        }
        else
        {
            ErrorCode = data;
        }
    }

    /// <summary>
    /// Creates a successful refresh token result.
    /// </summary>
    /// <param name="token">The newly issued refresh token.</param>
    /// <returns>A successful refresh token result containing the new token.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="token"/> is <see langword="null"/> or empty.
    /// </exception>
    public static RefreshTokenResult Success(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        return new RefreshTokenResult(true, token);
    }

    /// <summary>
    /// Creates a failed refresh token result.
    /// </summary>
    /// <param name="errorCode">The error code describing the failure.</param>
    /// <returns>A failed refresh token result containing the specified error code.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="errorCode"/> is <see langword="null"/> or empty.
    /// </exception>
    public static RefreshTokenResult Failure(string errorCode)
    {
        ArgumentException.ThrowIfNullOrEmpty(errorCode);

        return new RefreshTokenResult(false, errorCode);
    }
}