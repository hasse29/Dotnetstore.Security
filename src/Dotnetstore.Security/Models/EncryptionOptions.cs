using System.Security.Cryptography;
using Dotnetstore.Security.Internal;

namespace Dotnetstore.Security.Models;

/// <summary>
/// Configuration for the AES-256-GCM encryption handler.
/// </summary>
public sealed class EncryptionOptions
{
    internal const int KeySize = 32;

    /// <summary>
    /// Encryption keys keyed by key ID, each supplied as base64 and decoding to exactly 32 bytes.
    /// Generate one with <c>Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))</c> and keep it in a
    /// secret store, never next to the data it protects. Keep retired keys here for as long as data
    /// encrypted with them exists. IDs may contain letters, digits, <c>-</c> and <c>_</c>, up to 32 characters.
    /// </summary>
    public Dictionary<string, string> Keys { get; } = [];

    /// <summary>
    /// The ID of the key in <see cref="Keys"/> used to encrypt new values. Switching this to a new ID
    /// rotates the key: older values still decrypt, and <c>NeedsReEncryption</c> reports them.
    /// </summary>
    public string? CurrentKeyId { get; set; }

    internal Dictionary<string, byte[]> DecodeKeys()
    {
        if (Keys is null || Keys.Count == 0)
        {
            throw new ArgumentException("At least one encryption key must be configured.", nameof(Keys));
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
            if (base64 is null || !Convert.TryFromBase64String(base64, buffer, out var written) || written != KeySize)
            {
                CryptographicOperations.ZeroMemory(buffer);
                throw new ArgumentException(
                    $"Key '{id}' must be base64 and decode to exactly {KeySize} bytes.",
                    nameof(Keys));
            }

            decoded[id] = buffer[..written];
            CryptographicOperations.ZeroMemory(buffer);
        }

        return decoded;
    }
}
