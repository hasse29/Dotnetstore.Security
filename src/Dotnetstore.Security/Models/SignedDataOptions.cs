using System.Security.Cryptography;
using Dotnetstore.Security.Internal;

namespace Dotnetstore.Security.Models;

/// <summary>
/// Configuration for signing short-lived data such as email-verification and password-reset links.
/// </summary>
public sealed class SignedDataOptions
{
    internal const int MinKeySize = 32;

    /// <summary>
    /// HMAC keys keyed by key ID, each supplied as base64 and decoding to at least 32 bytes. Keep retired keys
    /// here until signed values made with them have expired. IDs may contain letters, digits, <c>-</c> and
    /// <c>_</c>, up to 32 characters.
    /// </summary>
    public Dictionary<string, string> Keys { get; } = [];

    /// <summary>The ID of the key in <see cref="Keys"/> used to sign new values.</summary>
    public string? CurrentKeyId { get; set; }

    /// <summary>How long a signed value is valid when no lifetime is given. Defaults to 1 hour.</summary>
    public TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromHours(1);

    internal Dictionary<string, byte[]> DecodeKeys()
    {
        if (DefaultLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(DefaultLifetime), DefaultLifetime, "Must be positive.");
        }

        if (Keys is null || Keys.Count == 0)
        {
            throw new ArgumentException("At least one signing key must be configured.", nameof(Keys));
        }

        if (CurrentKeyId is null || !Keys.ContainsKey(CurrentKeyId))
        {
            throw new ArgumentException("CurrentKeyId must match one of the configured keys.", nameof(CurrentKeyId));
        }

        var decoded = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var (id, base64) in Keys)
        {
            if (!KeyIdentifier.IsValid(id))
            {
                throw new ArgumentException(
                    $"Key ID '{id}' is invalid. Use 1-{KeyIdentifier.MaxLength} letters, digits, '-' or '_'.",
                    nameof(Keys));
            }

            var buffer = new byte[(base64?.Length ?? 0) * 3 / 4 + 3];
            if (base64 is null || !Convert.TryFromBase64String(base64, buffer, out var written) || written < MinKeySize)
            {
                CryptographicOperations.ZeroMemory(buffer);
                throw new ArgumentException(
                    $"Key '{id}' must be base64 and decode to at least {MinKeySize} bytes.",
                    nameof(Keys));
            }

            decoded[id] = buffer[..written];
            CryptographicOperations.ZeroMemory(buffer);
        }

        return decoded;
    }
}
