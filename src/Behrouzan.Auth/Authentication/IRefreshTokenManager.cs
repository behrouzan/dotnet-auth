namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Defines operations for managing refresh tokens.
/// </summary>
/// <typeparam name="TKey">The type of the user identifier.</typeparam>
public interface IRefreshTokenManager<TKey>
    where TKey : notnull
{
    /// <summary>
    /// Refreshes the supplied refresh token by rotating it and issuing
    /// a new refresh token when the current token is valid.
    /// </summary>
    /// <param name="refreshToken">The raw refresh token supplied by the client.</param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// A result containing the newly issued refresh token when successful,
    /// or an error code when the refresh operation fails.
    /// </returns>
    Task<RefreshTokenResult> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken = default);
}