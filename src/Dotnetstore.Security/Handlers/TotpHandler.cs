using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Dotnetstore.Security.Internal;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Handlers;

internal sealed class TotpHandler : ITotpHandler
{
    private readonly TotpOptions _options;
    private readonly TimeProvider _timeProvider;

    public TotpHandler(IOptions<TotpOptions> options, TimeProvider timeProvider)
        : this(options.Value, timeProvider)
    {
    }

    public TotpHandler(TotpOptions options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        options.Validate();
        _options = new TotpOptions
        {
            Digits = options.Digits,
            PeriodSeconds = options.PeriodSeconds,
            AllowedDriftSteps = options.AllowedDriftSteps,
        };
        _timeProvider = timeProvider;
    }

    public string GenerateSecret(int sizeInBytes = 20)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(sizeInBytes, 16);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(sizeInBytes, 64);

        return Base32.Encode(RandomNumberGenerator.GetBytes(sizeInBytes));
    }

    public string GenerateCode(string secret, DateTimeOffset? at = null)
    {
        var key = DecodeSecret(secret);
        return ComputeCode(key, TimeStep(at ?? _timeProvider.GetUtcNow()));
    }

    public bool Verify(string secret, string code, out long timeStep, long? lastUsedTimeStep = null)
    {
        timeStep = 0;

        if (string.IsNullOrEmpty(secret) || !Base32.TryDecode(secret, out var key))
        {
            return false;
        }

        var normalized = string.Concat((code ?? string.Empty).Where(c => c != ' '));
        if (normalized.Length != _options.Digits || !normalized.All(char.IsAsciiDigit))
        {
            return false;
        }

        var current = TimeStep(_timeProvider.GetUtcNow());
        var matched = false;

        // Check every step rather than stopping at the first match, so timing does not reveal which step matched.
        for (var step = current - _options.AllowedDriftSteps; step <= current + _options.AllowedDriftSteps; step++)
        {
            var isMatch = CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(ComputeCode(key, step)),
                Encoding.ASCII.GetBytes(normalized));

            if (isMatch && (lastUsedTimeStep is null || step > lastUsedTimeStep) && (!matched || step > timeStep))
            {
                matched = true;
                timeStep = step;
            }
        }

        return matched;
    }

    public Uri BuildProvisioningUri(string secret, string account, string issuer)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(account);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        _ = DecodeSecret(secret);

        var escapedIssuer = Uri.EscapeDataString(issuer);
        var label = $"{escapedIssuer}:{Uri.EscapeDataString(account)}";
        var normalizedSecret = string.Concat(secret.Where(c => c is not (' ' or '-' or '='))).ToUpperInvariant();

        return new Uri(string.Create(
            CultureInfo.InvariantCulture,
            $"otpauth://totp/{label}?secret={normalizedSecret}&issuer={escapedIssuer}&algorithm=SHA1&digits={_options.Digits}&period={_options.PeriodSeconds}"));
    }

    private static byte[] DecodeSecret(string secret)
    {
        if (string.IsNullOrEmpty(secret) || !Base32.TryDecode(secret, out var key))
        {
            throw new ArgumentException("The secret is not valid base32.", nameof(secret));
        }

        return key;
    }

    private long TimeStep(DateTimeOffset time) => time.ToUnixTimeSeconds() / _options.PeriodSeconds;

    [SuppressMessage("Security", "CA5350", Justification = "RFC 6238 and authenticator apps use HMAC-SHA1, which remains secure as an HMAC.")]
    private string ComputeCode(byte[] key, long counter)
    {
        Span<byte> message = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(message, counter);

        Span<byte> hash = stackalloc byte[HMACSHA1.HashSizeInBytes];
        HMACSHA1.HashData(key, message, hash);

        var offset = hash[^1] & 0x0F;
        var binary = BinaryPrimitives.ReadInt32BigEndian(hash.Slice(offset, 4)) & 0x7FFFFFFF;
        var modulus = _options.Digits == 8 ? 100_000_000 : 1_000_000;

        return (binary % modulus).ToString(CultureInfo.InvariantCulture).PadLeft(_options.Digits, '0');
    }
}
