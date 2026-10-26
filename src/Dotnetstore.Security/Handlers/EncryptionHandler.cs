using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Dotnetstore.Security.Internal;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// <see cref="IEncryptionHandler"/> backed by AES-256-GCM. Output has the form
/// <c>dse1.{keyId}.{base64url(nonce || ciphertext || tag)}</c> with a random 96-bit nonce per call.
/// Text is encrypted as its UTF-8 bytes, so text and binary payloads share one format.
/// </summary>
internal sealed class EncryptionHandler : IEncryptionHandler
{
    private const string Prefix = "dse1";
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly Dictionary<string, byte[]> _keys;
    private readonly string _currentKeyId;

    public EncryptionHandler(IOptions<EncryptionOptions> options)
        : this(options.Value)
    {
    }

    public EncryptionHandler(EncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _keys = options.DecodeKeys();
        _currentKeyId = options.CurrentKeyId!;
    }

    public string Encrypt(string plaintext) => Encrypt(plaintext, associatedData: null);

    public string Encrypt(string plaintext, string? associatedData)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return Encrypt(plaintext.AsSpan(), associatedData);
    }

    public string Encrypt(ReadOnlySpan<char> plaintext) => Encrypt(plaintext, associatedData: null);

    public string Encrypt(ReadOnlySpan<char> plaintext, string? associatedData)
    {
        var data = new byte[Encoding.UTF8.GetByteCount(plaintext)];
        Encoding.UTF8.GetBytes(plaintext, data);

        try
        {
            return Encrypt(data, associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    public string Encrypt(ReadOnlySpan<byte> plaintext) => Encrypt(plaintext, associatedData: null);

    public string Encrypt(ReadOnlySpan<byte> plaintext, string? associatedData)
    {
        var payload = new byte[NonceSize + plaintext.Length + TagSize];
        var nonce = payload.AsSpan(0, NonceSize);
        var ciphertext = payload.AsSpan(NonceSize, plaintext.Length);
        var tag = payload.AsSpan(NonceSize + plaintext.Length, TagSize);

        RandomNumberGenerator.Fill(nonce);

        using var aes = new AesGcm(_keys[_currentKeyId], TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, ToBytes(associatedData));

        return $"{Prefix}.{_currentKeyId}.{Base64Url.EncodeToString(payload)}";
    }

    public string Decrypt(string payload, string? associatedData = null) =>
        TryDecrypt(payload, out var plaintext, associatedData)
            ? plaintext!
            : throw new CryptographicException("Decryption failed.");

    public bool TryDecrypt(string payload, out string? plaintext, string? associatedData = null)
    {
        plaintext = null;

        if (!TryDecryptCore(payload, associatedData, out var data))
        {
            return false;
        }

        try
        {
            plaintext = Encoding.UTF8.GetString(data);
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }

    public byte[] DecryptBytes(string payload, string? associatedData = null) =>
        TryDecryptBytes(payload, out var plaintext, associatedData)
            ? plaintext!
            : throw new CryptographicException("Decryption failed.");

    public bool TryDecryptBytes(string payload, out byte[]? plaintext, string? associatedData = null)
    {
        var success = TryDecryptCore(payload, associatedData, out var data);
        plaintext = success ? data : null;
        return success;
    }

    public bool NeedsReEncryption(string payload) =>
        !TryParse(payload, out var keyId, out _)
        || !string.Equals(keyId, _currentKeyId, StringComparison.Ordinal);

    private bool TryDecryptCore(string? payload, string? associatedData, out byte[] data)
    {
        data = [];

        if (!TryParse(payload, out var keyId, out var raw) || !_keys.TryGetValue(keyId, out var key))
        {
            return false;
        }

        var nonce = raw.AsSpan(0, NonceSize);
        var ciphertext = raw.AsSpan(NonceSize, raw.Length - NonceSize - TagSize);
        var tag = raw.AsSpan(raw.Length - TagSize, TagSize);
        var buffer = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, buffer, ToBytes(associatedData));
            data = buffer;
            return true;
        }
        catch (CryptographicException)
        {
            CryptographicOperations.ZeroMemory(buffer);
            return false;
        }
    }

    private static byte[] ToBytes(string? associatedData) =>
        associatedData is null ? [] : Encoding.UTF8.GetBytes(associatedData);

    private static bool TryParse(string? payload, out string keyId, out byte[] raw)
    {
        keyId = string.Empty;
        raw = [];

        if (string.IsNullOrEmpty(payload))
        {
            return false;
        }

        var parts = payload.Split('.');
        if (parts.Length != 3 || parts[0] != Prefix || !KeyIdentifier.IsValid(parts[1]))
        {
            return false;
        }

        try
        {
            raw = Base64Url.DecodeFromChars(parts[2]);
        }
        catch (FormatException)
        {
            return false;
        }

        if (raw.Length < NonceSize + TagSize)
        {
            return false;
        }

        keyId = parts[1];
        return true;
    }
}
