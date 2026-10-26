using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// Creates and verifies API keys of the form <c>prefix.id.secret</c>. Store the <see cref="ApiKey.Id"/> and
/// <see cref="ApiKey.Hash"/>, look the record up by id, then verify the presented key against its hash.
/// </summary>
public interface IApiKeyHandler
{
    /// <summary>
    /// Creates a new API key.
    /// </summary>
    /// <param name="prefix">
    /// A short lowercase label such as <c>live</c> or <c>test</c>, 1 to 16 letters or digits, that makes keys
    /// recognizable and lets secret scanners find leaked ones.
    /// </param>
    /// <returns>The key to give to the client once, and the values to store.</returns>
    /// <exception cref="ArgumentException"><paramref name="prefix"/> is not 1 to 16 lowercase letters or digits.</exception>
    ApiKey Create(string prefix);

    /// <summary>
    /// Splits a presented key to find its public id, without checking the secret.
    /// </summary>
    /// <param name="value">The key presented by the client.</param>
    /// <param name="prefix">The key's prefix when parsing succeeds.</param>
    /// <param name="id">The key's id, for looking up the stored record, when parsing succeeds.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> has the expected shape.</returns>
    bool TryParse(string value, out string? prefix, out string? id);

    /// <summary>
    /// Checks a presented key against the hash stored for its id, in constant time.
    /// </summary>
    /// <param name="value">The key presented by the client.</param>
    /// <param name="storedHash">The stored <see cref="ApiKey.Hash"/> of the record found by id.</param>
    /// <returns><see langword="true"/> if the secret matches. Revocation and expiry must still be checked by the caller.</returns>
    bool Verify(string value, string storedHash);
}
