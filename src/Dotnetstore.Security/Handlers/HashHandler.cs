using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;
using Dotnetstore.Security.Internal;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// <see cref="IHashHandler"/> backed by Argon2id. Hashes are emitted in the PHC string format
/// <c>$argon2id$v=19$m=65536,t=3,p=4$salt$hash</c> (unpadded base64), so verification always
/// uses the parameters stored in the hash and cost parameters can be raised over time.
/// </summary>
internal sealed class HashHandler : IHashHandler
{
    private const int Version = 0x13;
    private const string Prefix = "argon2id";

    private readonly Argon2Options _options;
    private readonly Dictionary<string, byte[]> _peppers;
    private readonly string? _pepperId;

    /// <summary>Creates a handler with default <see cref="Argon2Options"/>.</summary>
    public HashHandler()
        : this(new Argon2Options())
    {
    }

    /// <summary>Creates a handler using the supplied options.</summary>
    /// <param name="options">The Argon2 cost and size settings.</param>
    /// <exception cref="ArgumentOutOfRangeException">An option value is outside the supported range.</exception>
    public HashHandler(IOptions<Argon2Options> options)
        : this(options.Value)
    {
    }

    /// <summary>Creates a handler using the supplied options.</summary>
    /// <param name="options">The Argon2 cost and size settings.</param>
    /// <exception cref="ArgumentOutOfRangeException">An option value is outside the supported range.</exception>
    public HashHandler(Argon2Options options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = new Argon2Options
        {
            MemorySizeKiB = options.MemorySizeKiB,
            Iterations = options.Iterations,
            DegreeOfParallelism = options.DegreeOfParallelism,
            SaltSize = options.SaltSize,
            HashSize = options.HashSize,
        };
        _peppers = options.DecodePeppers();
        _pepperId = options.CurrentPepperId;
    }

    /// <inheritdoc />
    public string Hash(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);
        return Hash(value.AsSpan());
    }

    /// <inheritdoc />
    public string Hash(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty)
        {
            throw new ArgumentException("Value must not be empty.", nameof(value));
        }

        var salt = RandomNumberGenerator.GetBytes(_options.SaltSize);
        var derived = Derive(
            value,
            salt,
            _options.MemorySizeKiB,
            _options.Iterations,
            _options.DegreeOfParallelism,
            _options.HashSize,
            _pepperId is null ? null : _peppers[_pepperId]);

        var keyId = _pepperId is null ? string.Empty : $",keyid={_pepperId}";

        return string.Create(
            CultureInfo.InvariantCulture,
            $"${Prefix}$v={Version}$m={_options.MemorySizeKiB},t={_options.Iterations},p={_options.DegreeOfParallelism}{keyId}${ToBase64(salt)}${ToBase64(derived)}");
    }

    /// <inheritdoc />
    public bool Verify(string value, string hash) =>
        value is not null && Verify(value.AsSpan(), hash);

    /// <inheritdoc />
    public bool Verify(ReadOnlySpan<char> value, string hash)
    {
        if (value.IsEmpty || !TryParse(hash, out var parsed))
        {
            return false;
        }

        byte[]? pepper = null;
        if (parsed.KeyId is not null && !_peppers.TryGetValue(parsed.KeyId, out pepper))
        {
            return false;
        }

        var actual = Derive(
            value,
            parsed.Salt,
            parsed.MemorySizeKiB,
            parsed.Iterations,
            parsed.DegreeOfParallelism,
            parsed.Hash.Length,
            pepper);

        return CryptographicOperations.FixedTimeEquals(actual, parsed.Hash);
    }

    /// <inheritdoc />
    public bool NeedsRehash(string hash)
    {
        if (!TryParse(hash, out var parsed))
        {
            return true;
        }

        return parsed.MemorySizeKiB != _options.MemorySizeKiB
            || parsed.Iterations != _options.Iterations
            || parsed.DegreeOfParallelism != _options.DegreeOfParallelism
            || parsed.Salt.Length != _options.SaltSize
            || parsed.Hash.Length != _options.HashSize
            || !string.Equals(parsed.KeyId, _pepperId, StringComparison.Ordinal);
    }

    private static byte[] Derive(
        ReadOnlySpan<char> value,
        byte[] salt,
        int memoryKiB,
        int iterations,
        int parallelism,
        int hashSize,
        byte[]? pepper)
    {
        var password = new byte[Encoding.UTF8.GetByteCount(value)];
        Encoding.UTF8.GetBytes(value, password);
        try
        {
            using var argon2 = new Argon2id(password)
            {
                Salt = salt,
                MemorySize = memoryKiB,
                Iterations = iterations,
                DegreeOfParallelism = parallelism,
                KnownSecret = pepper,
            };

            return argon2.GetBytes(hashSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
        }
    }

    private static bool TryParse(string? hash, out ParsedHash parsed)
    {
        parsed = default;

        if (string.IsNullOrEmpty(hash))
        {
            return false;
        }

        // "", "argon2id", "v=19", "m=..,t=..,p=..[,keyid=..]", salt, hash
        var parts = hash.Split('$');
        if (parts.Length != 6 || parts[0].Length != 0 || parts[1] != Prefix)
        {
            return false;
        }

        if (!TryParseVersion(parts[2]) || !TryParseCosts(parts[3], out var m, out var t, out var p, out var keyId))
        {
            return false;
        }

        if (!TryFromBase64(parts[4], out var salt) || !TryFromBase64(parts[5], out var derived))
        {
            return false;
        }

        if (salt.Length is < Argon2Options.MinSaltSize or > Argon2Options.MaxSaltSize
            || derived.Length is < Argon2Options.MinHashSize or > Argon2Options.MaxHashSize)
        {
            return false;
        }

        parsed = new ParsedHash(m, t, p, keyId, salt, derived);
        return true;
    }

    private static bool TryParseVersion(string segment) =>
        segment.StartsWith("v=", StringComparison.Ordinal)
        && int.TryParse(segment.AsSpan(2), NumberStyles.None, CultureInfo.InvariantCulture, out var version)
        && version == Version;

    private static bool TryParseCosts(string segment, out int m, out int t, out int p, out string? keyId)
    {
        m = t = p = 0;
        keyId = null;

        var fields = segment.Split(',');
        if (fields.Length is not (3 or 4)
            || !TryParseField(fields[0], "m=", out m)
            || !TryParseField(fields[1], "t=", out t)
            || !TryParseField(fields[2], "p=", out p))
        {
            return false;
        }

        if (fields.Length == 4)
        {
            if (!fields[3].StartsWith("keyid=", StringComparison.Ordinal)
                || !KeyIdentifier.IsValid(fields[3][6..]))
            {
                return false;
            }

            keyId = fields[3][6..];
        }

        // Bounds stop a tampered hash from forcing an enormous allocation or runtime.
        return m is >= Argon2Options.MinMemorySizeKiB and <= Argon2Options.MaxMemorySizeKiB
            && t is >= 1 and <= Argon2Options.MaxIterations
            && p is >= 1 and <= Argon2Options.MaxDegreeOfParallelism
            && m >= 8 * p;
    }

    private static bool TryParseField(string field, string name, out int value)
    {
        value = 0;
        return field.StartsWith(name, StringComparison.Ordinal)
            && int.TryParse(field.AsSpan(name.Length), NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    private static string ToBase64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    private static bool TryFromBase64(string segment, out byte[] bytes)
    {
        bytes = [];
        if (segment.Length == 0 || segment.Contains('=', StringComparison.Ordinal))
        {
            return false;
        }

        var padded = (segment.Length % 4) switch
        {
            0 => segment,
            2 => segment + "==",
            3 => segment + "=",
            _ => null,
        };

        if (padded is null)
        {
            return false;
        }

        try
        {
            bytes = Convert.FromBase64String(padded);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private readonly record struct ParsedHash(
        int MemorySizeKiB,
        int Iterations,
        int DegreeOfParallelism,
        string? KeyId,
        byte[] Salt,
        byte[] Hash);
}
