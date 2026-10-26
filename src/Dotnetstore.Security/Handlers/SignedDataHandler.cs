using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Dotnetstore.Security.Internal;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// <see cref="ISignedDataHandler"/> backed by HMAC-SHA256. Output has the form
/// <c>dsd1.{keyId}.{expiresUnixSeconds}.{base64url(payload)}.{base64url(mac)}</c>.
/// </summary>
internal sealed class SignedDataHandler : ISignedDataHandler
{
    private const string Prefix = "dsd1";

    private readonly Dictionary<string, byte[]> _keys;
    private readonly string _currentKeyId;
    private readonly TimeSpan _defaultLifetime;
    private readonly TimeProvider _timeProvider;

    public SignedDataHandler(IOptions<SignedDataOptions> options, TimeProvider timeProvider)
        : this(options.Value, timeProvider)
    {
    }

    public SignedDataHandler(SignedDataOptions options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _keys = options.DecodeKeys();
        _currentKeyId = options.CurrentKeyId!;
        _defaultLifetime = options.DefaultLifetime;
        _timeProvider = timeProvider;
    }

    public string Sign(string payload, string purpose, TimeSpan? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ValidatePurpose(purpose);

        var effectiveLifetime = lifetime ?? _defaultLifetime;
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(effectiveLifetime, TimeSpan.Zero);

        var expires = (_timeProvider.GetUtcNow() + effectiveLifetime).ToUnixTimeSeconds();
        var encodedPayload = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload));
        var mac = ComputeMac(_keys[_currentKeyId], _currentKeyId, expires, purpose, encodedPayload);

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{Prefix}.{_currentKeyId}.{expires}.{encodedPayload}.{Base64Url.EncodeToString(mac)}");
    }

    public bool TryValidate(string token, string purpose, out string? payload)
    {
        payload = null;

        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(purpose) || purpose.Contains('\n', StringComparison.Ordinal))
        {
            return false;
        }

        var parts = token.Split('.');
        if (parts.Length != 5
            || parts[0] != Prefix
            || !_keys.TryGetValue(parts[1], out var key)
            || !long.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var expires))
        {
            return false;
        }

        byte[] mac;
        byte[] payloadBytes;
        try
        {
            mac = Base64Url.DecodeFromChars(parts[4]);
            payloadBytes = Base64Url.DecodeFromChars(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        var expected = ComputeMac(key, parts[1], expires, purpose, parts[3]);
        if (!CryptographicOperations.FixedTimeEquals(expected, mac))
        {
            return false;
        }

        if (_timeProvider.GetUtcNow().ToUnixTimeSeconds() >= expires)
        {
            return false;
        }

        payload = Encoding.UTF8.GetString(payloadBytes);
        return true;
    }

    private static byte[] ComputeMac(byte[] key, string keyId, long expires, string purpose, string encodedPayload)
    {
        var message = string.Create(
            CultureInfo.InvariantCulture,
            $"{Prefix}\n{keyId}\n{expires}\n{purpose}\n{encodedPayload}");
        return HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(message));
    }

    private static void ValidatePurpose(string purpose)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(purpose);

        if (purpose.Contains('\n', StringComparison.Ordinal))
        {
            throw new ArgumentException("The purpose must not contain a line break.", nameof(purpose));
        }
    }
}
