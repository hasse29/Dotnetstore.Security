using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// Generates and verifies random secrets: password-reset and email-verification tokens, numeric codes, and
/// recovery codes. Only hashes are stored, so a database leak does not expose usable secrets.
/// </summary>
public interface ISecretHandler
{
    /// <summary>
    /// Generates a random URL-safe secret and its hash.
    /// </summary>
    /// <param name="sizeInBytes">The amount of randomness, from 16 to 128 bytes. Defaults to 32 (256 bits).</param>
    /// <returns>The secret for the user and the hash to store.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="sizeInBytes"/> is outside 16 to 128.</exception>
    GeneratedSecret Generate(int sizeInBytes = 32);

    /// <summary>
    /// Computes the hash of a secret presented by a user, for looking up its stored record.
    /// </summary>
    /// <param name="secret">The secret.</param>
    /// <returns>The hash, equal to <see cref="GeneratedSecret.Hash"/> for the secret it was generated with.</returns>
    string Hash(string secret);

    /// <summary>
    /// Checks a presented secret against a stored hash in constant time.
    /// </summary>
    /// <param name="secret">The secret presented by the user.</param>
    /// <param name="storedHash">The stored hash.</param>
    /// <returns><see langword="true"/> if they match. Expiry and single use must still be enforced by the caller.</returns>
    bool Verify(string secret, string storedHash);

    /// <summary>
    /// Generates a uniformly distributed numeric code such as an SMS or email verification code.
    /// Short codes are guessable, so always combine them with an expiry and an attempt limit.
    /// </summary>
    /// <param name="digits">The number of digits, from 4 to 9. Defaults to 6.</param>
    /// <returns>The code, zero-padded.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="digits"/> is outside 4 to 9.</exception>
    string GenerateCode(int digits = 6);

    /// <summary>
    /// Generates one-time recovery codes, for example backup codes for two-factor authentication.
    /// </summary>
    /// <param name="count">The number of codes, from 1 to 50. Defaults to 10.</param>
    /// <returns>The codes to show once, with the hash of each to store.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="count"/> is outside 1 to 50.</exception>
    IReadOnlyList<RecoveryCode> GenerateRecoveryCodes(int count = 10);

    /// <summary>
    /// Checks a recovery code against a stored hash. Case, spaces and dashes are ignored.
    /// </summary>
    /// <param name="code">The code typed by the user.</param>
    /// <param name="storedHash">The stored hash.</param>
    /// <returns><see langword="true"/> if they match. The caller must delete the hash so a code works only once.</returns>
    bool VerifyRecoveryCode(string code, string storedHash);

    /// <summary>
    /// Computes the hash of a recovery code typed by the user, for looking up its stored record.
    /// </summary>
    /// <param name="code">The code typed by the user.</param>
    /// <returns>The hash, equal to <see cref="RecoveryCode.Hash"/> for the code it was generated with.</returns>
    string HashRecoveryCode(string code);
}
