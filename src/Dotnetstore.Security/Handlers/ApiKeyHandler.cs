using System.Buffers.Text;
using System.Security.Cryptography;
using Dotnetstore.Security.Internal;
using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

internal sealed class ApiKeyHandler : IApiKeyHandler
{
    private const int MaxPrefixLength = 16;
    private const int IdSize = 8;
    private const int SecretSize = 32;

    public ApiKey Create(string prefix)
    {
        if (!IsValidPrefix(prefix))
        {
            throw new ArgumentException(
                $"The prefix must be 1 to {MaxPrefixLength} lowercase letters or digits.",
                nameof(prefix));
        }

        var id = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(IdSize));
        var secret = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(SecretSize));
        return new ApiKey($"{prefix}.{id}.{secret}", prefix, id, SecretHasher.Hash(secret));
    }

    public bool TryParse(string value, out string? prefix, out string? id) =>
        TryParseCore(value, out prefix, out id, out _);

    public bool Verify(string value, string storedHash) =>
        TryParseCore(value, out _, out _, out var secret) && SecretHasher.Verify(secret!, storedHash);

    private static bool TryParseCore(string? value, out string? prefix, out string? id, out string? secret)
    {
        prefix = id = secret = null;

        var parts = value?.Split('.');
        if (parts is not { Length: 3 } || !IsValidPrefix(parts[0]) || parts[1].Length == 0 || parts[2].Length == 0)
        {
            return false;
        }

        prefix = parts[0];
        id = parts[1];
        secret = parts[2];
        return true;
    }

    private static bool IsValidPrefix(string? prefix) =>
        prefix is { Length: >= 1 and <= MaxPrefixLength }
        && prefix.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c));
}
