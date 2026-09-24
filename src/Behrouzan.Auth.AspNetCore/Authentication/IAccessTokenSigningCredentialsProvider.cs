using Microsoft.IdentityModel.Tokens;

namespace Behrouzan.Auth.AspNetCore.Authentication;

/// <summary>
/// Supplies the signing credentials for the access token currently being issued.
/// </summary>
public interface IAccessTokenSigningCredentialsProvider
{
    /// <summary>
    /// Gets the signing credentials to use for the current access-token issuance.
    /// </summary>
    /// <returns>The signing credentials for the token being issued.</returns>
    SigningCredentials GetSigningCredentials();
}
