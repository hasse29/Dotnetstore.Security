namespace Dotnetstore.Security.Handlers;

/// <summary>
/// Signs short pieces of data so they can be handed to a user and trusted when returned, for example the user id
/// in an email-verification or password-reset link. The data is readable by the user but cannot be altered, and
/// it expires. For secret data use <see cref="IEncryptionHandler"/> instead.
/// </summary>
public interface ISignedDataHandler
{
    /// <summary>
    /// Signs <paramref name="payload"/> with the current key.
    /// </summary>
    /// <param name="payload">The data to sign, for example a user id.</param>
    /// <param name="purpose">
    /// What the value is for, such as <c>email-verification</c>. It is authenticated but not included in the output,
    /// so a value signed for one purpose is rejected for another.
    /// </param>
    /// <param name="lifetime">How long the value is valid. Uses the configured default when <see langword="null"/>.</param>
    /// <returns>A URL-safe string that embeds the key ID, expiry, payload and signature.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="payload"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="purpose"/> is empty or contains a line break.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="lifetime"/> is not positive.</exception>
    string Sign(string payload, string purpose, TimeSpan? lifetime = null);

    /// <summary>
    /// Checks the signature, purpose and expiry of a value and returns its payload.
    /// </summary>
    /// <param name="token">The value produced by <see cref="Sign"/>.</param>
    /// <param name="purpose">The purpose it must have been signed for.</param>
    /// <param name="payload">The original payload when validation succeeds; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> if the value is authentic, for this purpose, and not expired.</returns>
    bool TryValidate(string token, string purpose, out string? payload);
}
