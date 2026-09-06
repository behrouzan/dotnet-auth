using System.Text;
using System.Security.Cryptography;

internal sealed class RefreshTokenHasher
{
    public byte[] Hash(string refreshToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(refreshToken);
        
        var tokenBytes = Encoding.UTF8.GetBytes(refreshToken);
        return SHA256.HashData(tokenBytes);
    }
}