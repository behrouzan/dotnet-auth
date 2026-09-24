using Behrouzan.Auth.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace Sample.Api.TokenAuthentication;

internal sealed class SampleAccessTokenSigningCredentialsProvider
    : IAccessTokenSigningCredentialsProvider
{
    private readonly SecurityKey _signingKey;
    private readonly string _algorithm;

    public SampleAccessTokenSigningCredentialsProvider(
        SecurityKey signingKey,
        string algorithm)
    {
        _signingKey = signingKey;
        _algorithm = algorithm;
    }

    public SigningCredentials GetSigningCredentials()
    {
        return new SigningCredentials(_signingKey, _algorithm);
    }
}
