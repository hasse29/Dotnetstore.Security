using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace Dotnetstore.Security.Internal;

/// <summary>
/// Hashing for high-entropy random secrets (tokens, API key secrets, recovery codes). A fast hash is appropriate
/// here because the inputs cannot be guessed; use the Argon2 hash handler for human-chosen passwords.
/// </summary>
internal static class SecretHasher
{
    internal static string Hash(string secret) =>
        Base64Url.EncodeToString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));

    internal static bool Verify(string secret, string storedHash) =>
        !string.IsNullOrEmpty(secret)
        && !string.IsNullOrEmpty(storedHash)
        && CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(Hash(secret)),
            Encoding.UTF8.GetBytes(storedHash));
}
