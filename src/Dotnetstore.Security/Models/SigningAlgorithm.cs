namespace Dotnetstore.Security.Models;

/// <summary>
/// The algorithm used to sign and validate JWT access tokens.
/// </summary>
public enum SigningAlgorithm
{
    /// <summary>
    /// HMAC-SHA256 with a shared secret. Every service that validates tokens also holds the key that can sign them.
    /// </summary>
    HS256,

    /// <summary>
    /// RSASSA-PKCS1-v1_5 with SHA-256 and a key of at least 2048 bits. Services that only validate tokens need
    /// just the public key.
    /// </summary>
    RS256,

    /// <summary>
    /// ECDSA over curve P-256 with SHA-256. Services that only validate tokens need just the public key.
    /// </summary>
    ES256,
}
