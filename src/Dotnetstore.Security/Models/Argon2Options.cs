using Dotnetstore.Security.Internal;
using System.Security.Cryptography;

namespace Dotnetstore.Security.Models;

/// <summary>
/// Configuration for the Argon2id hash handler. Defaults follow the RFC 9106
/// "second recommended option" (64 MiB, 3 passes, 4 lanes).
/// </summary>
public sealed class Argon2Options
{
    internal const int MinMemorySizeKiB = 8;
    internal const int MaxMemorySizeKiB = 1_048_576;
    internal const int MaxIterations = 64;
    internal const int MaxDegreeOfParallelism = 64;
    internal const int MinSaltSize = 8;
    internal const int MaxSaltSize = 64;
    internal const int MinPepperSize = 16;
    internal const int MinHashSize = 16;
    internal const int MaxHashSize = 128;

    /// <summary>Memory cost in KiB. Defaults to 65536 (64 MiB).</summary>
    public int MemorySizeKiB { get; set; } = 65_536;

    /// <summary>Number of passes over memory (time cost). Defaults to 3.</summary>
    public int Iterations { get; set; } = 3;

    /// <summary>Number of parallel lanes. Defaults to 4.</summary>
    public int DegreeOfParallelism { get; set; } = 4;

    /// <summary>Salt length in bytes. Defaults to 16.</summary>
    public int SaltSize { get; set; } = 16;

    /// <summary>Derived hash length in bytes. Defaults to 32.</summary>
    public int HashSize { get; set; } = 32;

    /// <summary>
    /// Optional server-side secrets ("peppers"), keyed by pepper ID, each supplied as base64 and decoding to at
    /// least 16 bytes. Keep them out of the database, for example in a secret store. A pepper is mixed into the
    /// hash as the Argon2 secret input, and its ID is stored in the hash string (<c>keyid=</c>) so the matching
    /// pepper is found on verification. Keep retired peppers here for as long as hashes made with them exist.
    /// </summary>
    public Dictionary<string, string> Peppers { get; } = [];

    /// <summary>
    /// The ID of the pepper in <see cref="Peppers"/> used for new hashes. Required when <see cref="Peppers"/> is
    /// not empty. IDs may contain letters, digits, <c>-</c> and <c>_</c>, up to 32 characters. Switching this to
    /// a new ID rotates the pepper: <c>NeedsRehash</c> then reports hashes made with the old pepper.
    /// </summary>
    public string? CurrentPepperId { get; set; }

    internal Dictionary<string, byte[]> DecodePeppers()
    {
        var decoded = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        if (Peppers is null || Peppers.Count == 0)
        {
            if (CurrentPepperId is not null)
            {
                throw new ArgumentException("CurrentPepperId is set but no peppers are configured.", nameof(CurrentPepperId));
            }

            return decoded;
        }

        if (CurrentPepperId is null || !Peppers.ContainsKey(CurrentPepperId))
        {
            throw new ArgumentException("CurrentPepperId must match one of the configured peppers.", nameof(CurrentPepperId));
        }

        foreach (var (id, base64) in Peppers)
        {
            if (!KeyIdentifier.IsValid(id))
            {
                throw new ArgumentException(
                    $"Pepper ID '{id}' is invalid. Use 1-{KeyIdentifier.MaxLength} letters, digits, '-' or '_'.",
                    nameof(Peppers));
            }

            var buffer = new byte[(base64?.Length ?? 0) * 3 / 4 + 3];
            if (base64 is null || !Convert.TryFromBase64String(base64, buffer, out var written) || written < MinPepperSize)
            {
                CryptographicOperations.ZeroMemory(buffer);
                throw new ArgumentException(
                    $"Pepper '{id}' must be base64 and decode to at least {MinPepperSize} bytes.",
                    nameof(Peppers));
            }

            decoded[id] = buffer[..written];
            CryptographicOperations.ZeroMemory(buffer);
        }

        return decoded;
    }

    internal void Validate()
    {
        Check(MemorySizeKiB, MinMemorySizeKiB, MaxMemorySizeKiB, nameof(MemorySizeKiB));
        Check(Iterations, 1, MaxIterations, nameof(Iterations));
        Check(DegreeOfParallelism, 1, MaxDegreeOfParallelism, nameof(DegreeOfParallelism));
        Check(SaltSize, MinSaltSize, MaxSaltSize, nameof(SaltSize));
        Check(HashSize, MinHashSize, MaxHashSize, nameof(HashSize));
        _ = DecodePeppers();

        if (MemorySizeKiB < 8 * DegreeOfParallelism)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MemorySizeKiB),
                MemorySizeKiB,
                "Memory size must be at least 8 KiB per lane of parallelism.");
        }
    }

    private static void Check(int value, int min, int max, string name)
    {
        if (value < min || value > max)
        {
            throw new ArgumentOutOfRangeException(name, value, $"Must be between {min} and {max}.");
        }
    }
}
