namespace Behrouzan.Auth.Permissions;

/// <summary>
/// Represents the result of a permission management operation.
/// </summary>
public sealed class PermissionManagementResult
{
    /// <summary>
    /// Gets a value indicating whether the operation succeeded.
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// Gets the error code when the operation fails; otherwise, <see langword="null"/>.
    /// </summary>
    public PermissionManagementErrorCode? ErrorCode { get; }

    private PermissionManagementResult(
        bool isSuccess,
        PermissionManagementErrorCode? errorCode)
    {
        IsSuccess = isSuccess;
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Creates a successful permission management result.
    /// </summary>
    /// <returns>A successful result.</returns>
    public static PermissionManagementResult Success()
    {
        return new PermissionManagementResult(true, null);
    }

    /// <summary>
    /// Creates a failed permission management result with the specified error code.
    /// </summary>
    /// <param name="errorCode">The error code describing the failure.</param>
    /// <returns>A failed result containing the specified error code.</returns>
    public static PermissionManagementResult Failure(
        PermissionManagementErrorCode errorCode)
    {
        return new PermissionManagementResult(false, errorCode);
    }
}