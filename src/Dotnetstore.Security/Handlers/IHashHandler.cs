namespace Dotnetstore.Security.Handlers;

/// <summary>
/// Hashes and verifies secrets such as passwords using a self-describing, salted hash format.
/// </summary>
public interface IHashHandler
{
    /// <summary>
    /// Hashes <paramref name="value"/> with a freshly generated random salt.
    /// </summary>
    /// <param name="value">The secret to hash. Must not be empty.</param>
    /// <returns>A self-describing hash string that embeds the algorithm, parameters, and salt.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="value"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="value"/> is empty.</exception>
    string Hash(string value);

    /// <summary>
    /// Hashes <paramref name="value"/> with a freshly generated random salt, without requiring a string allocation.
    /// </summary>
    /// <param name="value">The secret to hash, as UTF-16 characters. Must not be empty.</param>
    /// <returns>A self-describing hash string that embeds the algorithm, parameters, and salt.</returns>
    /// <exception cref="ArgumentException"><paramref name="value"/> is empty.</exception>
    string Hash(ReadOnlySpan<char> value);

    /// <summary>
    /// Verifies <paramref name="value"/> against a hash previously produced by <see cref="Hash(string)"/>.
    /// </summary>
    /// <param name="value">The secret to check.</param>
    /// <param name="hash">The stored hash string.</param>
    /// <returns>
    /// <see langword="true"/> if the secret matches; <see langword="false"/> if it does not
    /// or if <paramref name="hash"/> is malformed or uses unsupported parameters.
    /// </returns>
    bool Verify(string value, string hash);

    /// <summary>
    /// Verifies <paramref name="value"/> against a hash previously produced by <see cref="Hash(string)"/>, without requiring a string allocation.
    /// </summary>
    /// <param name="value">The secret to check, as UTF-16 characters.</param>
    /// <param name="hash">The stored hash string.</param>
    /// <returns>
    /// <see langword="true"/> if the secret matches; <see langword="false"/> if it does not
    /// or if <paramref name="hash"/> is malformed or uses unsupported parameters.
    /// </returns>
    bool Verify(ReadOnlySpan<char> value, string hash);

    /// <summary>
    /// Determines whether <paramref name="hash"/> should be recomputed because it was created
    /// with parameters different from the current configuration.
    /// </summary>
    /// <param name="hash">The stored hash string.</param>
    /// <returns>
    /// <see langword="true"/> if the hash is malformed or outdated and should be replaced
    /// after the next successful <see cref="Verify(string, string)"/>.
    /// </returns>
    bool NeedsRehash(string hash);
}
