namespace Dotnetstore.Security.Internal;

/// <summary>RFC 4648 base32, the encoding authenticator apps expect for TOTP secrets.</summary>
internal static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    internal static string Encode(ReadOnlySpan<byte> data)
    {
        var chars = new char[(data.Length * 8 + 4) / 5];
        var buffer = 0;
        var bits = 0;
        var index = 0;

        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;

            while (bits >= 5)
            {
                chars[index++] = Alphabet[(buffer >> (bits - 5)) & 31];
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            chars[index] = Alphabet[(buffer << (5 - bits)) & 31];
        }

        return new string(chars);
    }

    /// <summary>Decodes base32, ignoring case, spaces, dashes and padding. Returns false for any other character.</summary>
    internal static bool TryDecode(string text, out byte[] data)
    {
        data = [];
        var result = new List<byte>(text.Length * 5 / 8);
        var buffer = 0;
        var bits = 0;

        foreach (var c in text)
        {
            if (c is ' ' or '-' or '=')
            {
                continue;
            }

            var value = Alphabet.IndexOf(char.ToUpperInvariant(c), StringComparison.Ordinal);
            if (value < 0)
            {
                return false;
            }

            buffer = (buffer << 5) | value;
            bits += 5;

            if (bits >= 8)
            {
                result.Add((byte)((buffer >> (bits - 8)) & 0xFF));
                bits -= 8;
            }
        }

        data = [.. result];
        return data.Length > 0;
    }
}
