using System.Security.Cryptography;

namespace Dotnetstore.Security;

/// <summary>
/// Generates secrets and keys in the formats the options in this library expect. Generate them once, store them
/// in a secret store, and never commit them to source control.
/// </summary>
public static class KeyGenerator
{
    /// <summary>
    /// Generates a random base64 secret, suitable for <c>TokenOptions.SigningKeys</c> with HS256 and for
    /// <c>SignedDataOptions.Keys</c>.
    /// </summary>
    /// <param name="sizeInBytes">The secret length in bytes. Must be at least 32. Defaults to 64.</param>
    /// <returns>The base64-encoded secret.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="sizeInBytes"/> is below 32.</exception>
    public static string CreateSecret(int sizeInBytes = 64)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(sizeInBytes, 32);
        return Convert.ToBase64String(RandomNumberGenerator.GetBytes(sizeInBytes));
    }

    /// <summary>Generates a 256-bit key for <c>EncryptionOptions.Keys</c>.</summary>
    /// <returns>The base64-encoded key.</returns>
    public static string CreateEncryptionKey() => CreateSecret(32);

    /// <summary>Generates a pepper for <c>Argon2Options.Peppers</c>.</summary>
    /// <returns>The base64-encoded pepper.</returns>
    public static string CreatePepper() => CreateSecret(32);

    /// <summary>Generates an RSA key pair for RS256.</summary>
    /// <param name="keySizeInBits">The key size. Must be at least 2048. Defaults to 3072.</param>
    /// <returns>The private and public keys, PEM-encoded. Give the private key to the issuer and the public key to services that only validate.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="keySizeInBits"/> is below 2048.</exception>
    public static (string PrivateKeyPem, string PublicKeyPem) CreateRsaKeyPair(int keySizeInBits = 3072)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(keySizeInBits, 2048);

        using var rsa = RSA.Create(keySizeInBits);
        return (rsa.ExportPkcs8PrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
    }

    /// <summary>Generates a P-256 key pair for ES256.</summary>
    /// <returns>The private and public keys, PEM-encoded. Give the private key to the issuer and the public key to services that only validate.</returns>
    public static (string PrivateKeyPem, string PublicKeyPem) CreateEcKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (ecdsa.ExportPkcs8PrivateKeyPem(), ecdsa.ExportSubjectPublicKeyInfoPem());
    }
}
