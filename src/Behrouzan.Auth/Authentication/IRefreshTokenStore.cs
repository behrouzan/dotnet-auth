namespace Behrouzan.Auth.Authentication;

/// <summary>
/// Defines the persistence operations required for refresh tokens.
/// </summary>
/// <typeparam name="TKey">The type of the user identifier.</typeparam>
public interface IRefreshTokenStore<TKey>
    where TKey : notnull
{
    /// <summary>
    /// Persists a newly created refresh token.
    /// </summary>
    /// <param name="refreshToken">The data required to persist the refresh token.</param>
    /// <param name="cancellationToken">A token used to cancel the asynchronous operation.</param>
    /// <returns>A task that represents the asynchronous persistence operation.</returns>
    Task InsertAsync(
        RefreshTokenCreateData<TKey> refreshToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds a refresh token by its cryptographic hash.
    /// </summary>
    /// <param name="tokenHash">The cryptographic hash of the refresh token to find.</param>
    /// <param name="cancellationToken">A token used to cancel the asynchronous operation.</param>
    /// <returns>
    /// A task whose result contains the refresh token data if found;
    /// otherwise, <see langword="null"/>.
    /// </returns>
    Task<RefreshTokenData<TKey>?> FindByHashAsync(
        byte[] tokenHash,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists the revocation of an existing refresh token.
    /// </summary>
    /// <param name="refreshToken">The data describing the refresh token revocation.</param>
    /// <param name="cancellationToken">A token used to cancel the asynchronous operation.</param>
    /// <returns>A task that represents the asynchronous persistence operation.</returns>
    Task SaveRevocationAsync(
        RefreshTokenRevocationData refreshToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes every active, unexpired refresh token owned by a user in one
    /// persistence operation.
    /// </summary>
    /// <param name="userId">The identifier of the token owner.</param>
    /// <param name="revokedAt">The operation timestamp used for revocation and expiry filtering.</param>
    /// <param name="revocationReason">The reason recorded on affected tokens.</param>
    /// <param name="cancellationToken">A token used to cancel the asynchronous operation.</param>
    /// <returns>A task that represents the bulk persistence operation.</returns>
    Task RevokeAllAsync(
        TKey userId,
        DateTimeOffset revokedAt,
        RefreshTokenRevocationReason revocationReason,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically persists a refresh token rotation by revoking the current
    /// token and storing its replacement.
    /// </summary>
    /// <param name="currentToken">The data describing the rotation of the current token.</param>
    /// <param name="newToken">The data required to persist the replacement token.</param>
    /// <param name="cancellationToken">A token used to cancel the asynchronous operation.</param>
    /// <returns>
    /// A task whose result indicates whether the rotation was persisted
    /// successfully and, when it was not, provides the current revocation state.
    /// </returns>
    Task<RefreshTokenRotationResult> SaveRotationAsync(
        RefreshTokenRotationData currentToken,
        RefreshTokenCreateData<TKey> newToken,
        CancellationToken cancellationToken = default);
}
