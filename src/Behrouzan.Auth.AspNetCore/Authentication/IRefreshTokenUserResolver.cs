namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Resolves a stored refresh-token owner to the current Identity user.
/// </summary>
/// <typeparam name="TUser">The application user type.</typeparam>
/// <typeparam name="TKey">The type of the persisted user identifier.</typeparam>
public interface IRefreshTokenUserResolver<TUser, TKey>
    where TUser : class
    where TKey : notnull
{
    /// <summary>Resolves the current user for a server-validated refresh-token owner.</summary>
    /// <param name="userId">The owner obtained from stored refresh-token data.</param>
    /// <param name="cancellationToken">A token used to cancel the operation.</param>
    /// <returns>The current user, or <see langword="null"/> when the user no longer exists.</returns>
    Task<TUser?> ResolveAsync(TKey userId, CancellationToken cancellationToken = default);
}
