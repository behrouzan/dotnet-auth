namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Identifies an authenticated user for refresh-token persistence and JWT issuance.
/// </summary>
/// <typeparam name="TKey">The type of the persisted user identifier.</typeparam>
public sealed class TokenUserIdentity<TKey>
    where TKey : notnull
{
    /// <summary>
    /// Initializes a new token user identity.
    /// </summary>
    /// <param name="userId">The user identifier used by refresh-token persistence.</param>
    /// <param name="subject">The canonical Identity user identifier used as the JWT subject.</param>
    public TokenUserIdentity(TKey userId, string subject)
    {
        ArgumentNullException.ThrowIfNull(userId);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        UserId = userId;
        Subject = subject;
    }

    /// <summary>
    /// Gets the user identifier used by refresh-token persistence.
    /// </summary>
    public TKey UserId { get; }

    /// <summary>
    /// Gets the canonical Identity user identifier used as the JWT subject.
    /// </summary>
    public string Subject { get; }
}
