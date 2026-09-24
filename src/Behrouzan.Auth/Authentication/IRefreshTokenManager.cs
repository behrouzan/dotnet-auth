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
    /// A result containing the newly issued refresh token and its owner from
    /// validated stored data when successful, or an error code when refresh fails.
    /// </returns>
    Task<RefreshTokenRenewalResult<TKey>> RefreshAsync(
        string refreshToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a refresh token without rotating or otherwise mutating it.
    /// </summary>
    /// <param name="refreshToken">The raw refresh token supplied by the client.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The owner read from validated stored token data, or an existing error code.</returns>
    Task<RefreshTokenValidationResult<TKey>> ValidateAsync(
        string refreshToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new refresh token for the specified user and stores
    /// its hash and metadata in the configured refresh token store.
    /// </summary>
    /// <param name="userId">
    /// The identifier of the user for whom the refresh token is created.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// A result containing the newly issued raw refresh token.
    /// </returns>
    Task<RefreshTokenResult> CreateAsync(
        TKey userId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the specified refresh token if it is currently active.
    /// </summary>
    /// <param name="refreshToken">
    /// The raw refresh token to revoke.
    /// </param>
    /// <param name="cancellationToken">
    /// A token that can be used to cancel the asynchronous operation.
    /// </param>
    /// <returns>
    /// A task that represents the asynchronous revocation operation.
    /// </returns>
    /// <remarks>
    /// The operation is idempotent. If the token does not exist, has expired,
    /// or has already been revoked, the operation completes successfully
    /// without modifying its existing state.
    /// </remarks>
    Task RevokeAsync(
        string refreshToken,
        CancellationToken cancellationToken = default);
}
