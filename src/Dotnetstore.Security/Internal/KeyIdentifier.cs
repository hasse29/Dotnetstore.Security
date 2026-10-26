namespace Dotnetstore.Security.Internal;

internal static class KeyIdentifier
{
    internal const int MaxLength = 32;

    internal static bool IsValid(string? id) =>
        id is { Length: >= 1 and <= MaxLength }
        && id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
}
