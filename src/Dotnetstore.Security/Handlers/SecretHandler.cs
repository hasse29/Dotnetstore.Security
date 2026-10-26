using System.Buffers.Text;
using System.Globalization;
using System.Security.Cryptography;
using Dotnetstore.Security.Internal;
using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

internal sealed class SecretHandler : ISecretHandler
{
    // 32 symbols without the look-alikes 0/O and 1/I, so a byte maps to a symbol without bias.
    private const string RecoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private const int RecoveryGroupSize = 5;

    public GeneratedSecret Generate(int sizeInBytes = 32)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(sizeInBytes, 16);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(sizeInBytes, 128);

        var value = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(sizeInBytes));
        return new GeneratedSecret(value, SecretHasher.Hash(value));
    }

    public string Hash(string secret)
    {
        ArgumentException.ThrowIfNullOrEmpty(secret);
        return SecretHasher.Hash(secret);
    }

    public bool Verify(string secret, string storedHash) => SecretHasher.Verify(secret, storedHash);

    public string GenerateCode(int digits = 6)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(digits, 4);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(digits, 9);

        var limit = (int)Math.Pow(10, digits);
        return RandomNumberGenerator.GetInt32(limit).ToString(CultureInfo.InvariantCulture).PadLeft(digits, '0');
    }

    public IReadOnlyList<RecoveryCode> GenerateRecoveryCodes(int count = 10)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(count, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, 50);

        var codes = new List<RecoveryCode>(count);
        for (var i = 0; i < count; i++)
        {
            var raw = new char[RecoveryGroupSize * 2];
            var random = RandomNumberGenerator.GetBytes(raw.Length);
            for (var j = 0; j < raw.Length; j++)
            {
                raw[j] = RecoveryAlphabet[random[j] & 31];
            }

            var plain = new string(raw);
            var display = $"{plain[..RecoveryGroupSize]}-{plain[RecoveryGroupSize..]}";
            codes.Add(new RecoveryCode(display, SecretHasher.Hash(plain)));
        }

        return codes;
    }

    public bool VerifyRecoveryCode(string code, string storedHash) =>
        !string.IsNullOrEmpty(code) && SecretHasher.Verify(Normalize(code), storedHash);

    public string HashRecoveryCode(string code)
    {
        ArgumentException.ThrowIfNullOrEmpty(code);
        return SecretHasher.Hash(Normalize(code));
    }

    private static string Normalize(string code) =>
        string.Concat(code.Where(c => c is not ('-' or ' ')))
            .ToUpperInvariant();
}
