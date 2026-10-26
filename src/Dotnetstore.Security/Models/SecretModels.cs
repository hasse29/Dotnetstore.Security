namespace Dotnetstore.Security.Models;

/// <summary>
/// A random secret and the hash to store for it.
/// </summary>
/// <param name="Value">The secret to give to the user, for example in a reset link. It cannot be recovered later.</param>
/// <param name="Hash">The value to store and look the secret up by.</param>
public sealed record GeneratedSecret(string Value, string Hash);

/// <summary>
/// A one-time recovery code and the hash to store for it.
/// </summary>
/// <param name="Code">The code to show to the user once, formatted for reading, for example <c>ABCDE-FGHJK</c>.</param>
/// <param name="Hash">The value to store. Delete it when the code is used.</param>
public sealed record RecoveryCode(string Code, string Hash);

/// <summary>
/// An API key and the values to store for it.
/// </summary>
/// <param name="Value">The full key to give to the client once, in the form <c>prefix.id.secret</c>.</param>
/// <param name="Prefix">The key's prefix, which identifies its kind or environment.</param>
/// <param name="Id">The public identifier to look the stored record up by.</param>
/// <param name="Hash">The hash of the secret part, to store alongside <paramref name="Id"/>.</param>
public sealed record ApiKey(string Value, string Prefix, string Id, string Hash);
