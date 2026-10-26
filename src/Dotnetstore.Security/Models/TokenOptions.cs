using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Dotnetstore.Security.Internal;
using Microsoft.IdentityModel.Tokens;

namespace Dotnetstore.Security.Models;

/// <summary>
/// Configuration for the JWT access token and refresh token handler.
/// </summary>
public sealed class TokenOptions
{
    internal const int MinSymmetricKeySize = 32;
    internal const int MinRsaKeySize = 2048;
    private const string P256Oid = "1.2.840.10045.3.1.7";

    /// <summary>The algorithm used to sign and validate access tokens. Defaults to <see cref="SigningAlgorithm.HS256"/>.</summary>
    public SigningAlgorithm Algorithm { get; set; } = SigningAlgorithm.HS256;

    /// <summary>The <c>iss</c> claim written to, and required on, every access token.</summary>
    public string Issuer { get; set; } = string.Empty;

    /// <summary>The <c>aud</c> claim written to, and required on, every access token.</summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// Keys keyed by key ID, written to the token header as <c>kid</c>. Keep retired keys here until tokens
    /// signed with them have expired. IDs may contain letters, digits, <c>-</c> and <c>_</c>, up to 32 characters.
    /// <para>
    /// For <see cref="SigningAlgorithm.HS256"/> each value is a base64 secret of at least 32 bytes; generate one with
    /// <c>Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))</c>.
    /// </para>
    /// <para>
    /// For <see cref="SigningAlgorithm.RS256"/> and <see cref="SigningAlgorithm.ES256"/> each value is a PEM key:
    /// a private key (<c>-----BEGIN PRIVATE KEY-----</c>) can sign and validate, a public key
    /// (<c>-----BEGIN PUBLIC KEY-----</c>) can only validate. Services that only validate tokens should be given
    /// public keys only. RSA keys must be at least 2048 bits and EC keys must use curve P-256.
    /// </para>
    /// </summary>
    public Dictionary<string, string> SigningKeys { get; } = [];

    /// <summary>
    /// The ID of the key in <see cref="SigningKeys"/> used to sign new access tokens. Required for
    /// <see cref="SigningAlgorithm.HS256"/>. For asymmetric algorithms it must name a private key; leave it
    /// <see langword="null"/> on services that only validate tokens, which then cannot create access tokens.
    /// </summary>
    public string? CurrentSigningKeyId { get; set; }

    /// <summary>How long an access token is valid. Defaults to 15 minutes.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long a refresh token is valid. Defaults to 7 days.</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>Tolerated clock difference when validating token lifetimes. Defaults to 30 seconds.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    internal string AlgorithmName => Algorithm switch
    {
        SigningAlgorithm.HS256 => SecurityAlgorithms.HmacSha256,
        SigningAlgorithm.RS256 => SecurityAlgorithms.RsaSha256,
        SigningAlgorithm.ES256 => SecurityAlgorithms.EcdsaSha256,
        _ => throw new ArgumentOutOfRangeException(nameof(Algorithm), Algorithm, "Unsupported algorithm."),
    };

    /// <summary>
    /// Validates the options and builds the key objects. The caller owns the returned keys and must dispose them.
    /// </summary>
    internal (List<SecurityKey> Keys, SecurityKey? Signing) Build()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
        {
            throw new ArgumentException("Issuer must be set.", nameof(Issuer));
        }

        if (string.IsNullOrWhiteSpace(Audience))
        {
            throw new ArgumentException("Audience must be set.", nameof(Audience));
        }

        if (AccessTokenLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(AccessTokenLifetime), AccessTokenLifetime, "Must be positive.");
        }

        if (RefreshTokenLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(RefreshTokenLifetime), RefreshTokenLifetime, "Must be positive.");
        }

        if (ClockSkew < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(ClockSkew), ClockSkew, "Must not be negative.");
        }

        _ = AlgorithmName;

        if (SigningKeys is null || SigningKeys.Count == 0)
        {
            throw new ArgumentException("At least one signing key must be configured.", nameof(SigningKeys));
        }

        if (CurrentSigningKeyId is not null && !SigningKeys.ContainsKey(CurrentSigningKeyId))
        {
            throw new ArgumentException(
                "CurrentSigningKeyId must match one of the configured signing keys.",
                nameof(CurrentSigningKeyId));
        }

        if (CurrentSigningKeyId is null && Algorithm == SigningAlgorithm.HS256)
        {
            throw new ArgumentException("CurrentSigningKeyId must be set for HS256.", nameof(CurrentSigningKeyId));
        }

        var keys = new List<SecurityKey>();
        SecurityKey? signing = null;

        try
        {
            foreach (var (id, value) in SigningKeys)
            {
                if (!KeyIdentifier.IsValid(id))
                {
                    throw new ArgumentException(
                        $"Signing key ID '{id}' is invalid. Use 1-{KeyIdentifier.MaxLength} letters, digits, '-' or '_'.",
                        nameof(SigningKeys));
                }

                var isPrivate = true;
                var key = Algorithm == SigningAlgorithm.HS256
                    ? BuildSymmetric(id, value)
                    : BuildAsymmetric(id, value, out isPrivate);
                keys.Add(key);

                if (isPrivate && CurrentSigningKeyId is null)
                {
                    throw new ArgumentException(
                        $"Signing key '{id}' is a private key, so CurrentSigningKeyId must be set.",
                        nameof(CurrentSigningKeyId));
                }

                if (id == CurrentSigningKeyId)
                {
                    if (!isPrivate)
                    {
                        throw new ArgumentException(
                            "CurrentSigningKeyId must name a private key, but it names a public key.",
                            nameof(CurrentSigningKeyId));
                    }

                    signing = key;
                }
            }

            return (keys, signing);
        }
        catch
        {
            DisposeKeys(keys);
            throw;
        }
    }

    internal static void DisposeKeys(IEnumerable<SecurityKey> keys)
    {
        foreach (var key in keys)
        {
            switch (key)
            {
                case RsaSecurityKey { Rsa: { } rsa }:
                    rsa.Dispose();
                    break;
                case ECDsaSecurityKey ecdsaKey:
                    ecdsaKey.ECDsa.Dispose();
                    break;
            }
        }
    }

    private static SymmetricSecurityKey BuildSymmetric(string id, string? base64)
    {
        var buffer = new byte[(base64?.Length ?? 0) * 3 / 4 + 3];
        if (base64 is null
            || !Convert.TryFromBase64String(base64, buffer, out var written)
            || written < MinSymmetricKeySize)
        {
            CryptographicOperations.ZeroMemory(buffer);
            throw new ArgumentException(
                $"Signing key '{id}' must be base64 and decode to at least {MinSymmetricKeySize} bytes.");
        }

        var secret = buffer[..written];
        CryptographicOperations.ZeroMemory(buffer);
        return new SymmetricSecurityKey(secret) { KeyId = id };
    }

    private SecurityKey BuildAsymmetric(string id, string? pem, out bool isPrivate)
    {
        isPrivate = false;

        if (pem is null || !PemEncoding.TryFind(pem, out var fields))
        {
            throw new ArgumentException($"Signing key '{id}' must be a PEM-encoded key.");
        }

        isPrivate = pem[fields.Label].EndsWith("PRIVATE KEY", StringComparison.Ordinal);

        try
        {
            return Algorithm == SigningAlgorithm.RS256 ? BuildRsa(id, pem) : BuildEcdsa(id, pem);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw new ArgumentException(
                $"Signing key '{id}' is not a valid {Algorithm} key: {ex.Message}",
                ex);
        }
    }

    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership passes to the returned key; disposed on failure.")]
    private static RsaSecurityKey BuildRsa(string id, string pem)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            if (rsa.KeySize < MinRsaKeySize)
            {
                throw new CryptographicException($"RSA keys must be at least {MinRsaKeySize} bits.");
            }

            return new RsaSecurityKey(rsa) { KeyId = id };
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership passes to the returned key; disposed on failure.")]
    private static ECDsaSecurityKey BuildEcdsa(string id, string pem)
    {
        var ecdsa = ECDsa.Create();
        try
        {
            ecdsa.ImportFromPem(pem);
            if (ecdsa.ExportParameters(false).Curve.Oid.Value != P256Oid)
            {
                throw new CryptographicException("EC keys must use curve P-256.");
            }

            return new ECDsaSecurityKey(ecdsa) { KeyId = id };
        }
        catch
        {
            ecdsa.Dispose();
            throw;
        }
    }
}
