namespace Dotnetstore.Security.Handlers;

/// <summary>
/// Encrypts and decrypts strings with authenticated encryption. Unlike hashing, encryption is reversible:
/// use it only when the original value must be recovered.
/// </summary>
public interface IEncryptionHandler
{
    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with the current key and a fresh random nonce.
    /// </summary>
    /// <param name="plaintext">The text to encrypt. May be empty.</param>
    /// <returns>A self-describing, URL-safe string that embeds the key ID, nonce, and authentication tag.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="plaintext"/> is <see langword="null"/>.</exception>
    string Encrypt(string plaintext);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with the current key, binding it to <paramref name="associatedData"/>.
    /// </summary>
    /// <param name="plaintext">The text to encrypt. May be empty.</param>
    /// <param name="associatedData">
    /// Context, such as a record ID, that is authenticated but not stored. The same value must be supplied to
    /// decrypt, which prevents a ciphertext from being moved to another record. <see langword="null"/> means none.
    /// </param>
    /// <returns>A self-describing, URL-safe string that embeds the key ID, nonce, and authentication tag.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="plaintext"/> is <see langword="null"/>.</exception>
    string Encrypt(string plaintext, string? associatedData);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with the current key and a fresh random nonce, without requiring a string allocation.
    /// </summary>
    /// <param name="plaintext">The text to encrypt, as UTF-16 characters. May be empty.</param>
    /// <returns>A self-describing, URL-safe string that embeds the key ID, nonce, and authentication tag.</returns>
    string Encrypt(ReadOnlySpan<char> plaintext);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with the current key, binding it to <paramref name="associatedData"/>, without requiring a string allocation.
    /// </summary>
    /// <param name="plaintext">The text to encrypt, as UTF-16 characters. May be empty.</param>
    /// <param name="associatedData">Authenticated context; see <see cref="Encrypt(string, string?)"/>.</param>
    /// <returns>A self-describing, URL-safe string that embeds the key ID, nonce, and authentication tag.</returns>
    string Encrypt(ReadOnlySpan<char> plaintext, string? associatedData);

    /// <summary>
    /// Decrypts a value produced by <see cref="Encrypt(string, string?)"/>.
    /// </summary>
    /// <param name="payload">The encrypted string.</param>
    /// <param name="associatedData">The same context that was supplied to encrypt, if any.</param>
    /// <returns>The original text.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// The payload is malformed, was tampered with, uses an unknown key, or the associated data does not match.
    /// The cause is deliberately not distinguished.
    /// </exception>
    string Decrypt(string payload, string? associatedData = null);

    /// <summary>
    /// Attempts to decrypt a value produced by <see cref="Encrypt(string, string?)"/>.
    /// </summary>
    /// <param name="payload">The encrypted string.</param>
    /// <param name="plaintext">The original text when decryption succeeds; otherwise <see langword="null"/>.</param>
    /// <param name="associatedData">The same context that was supplied to encrypt, if any.</param>
    /// <returns><see langword="true"/> if decryption and authentication succeeded.</returns>
    bool TryDecrypt(string payload, out string? plaintext, string? associatedData = null);

    /// <summary>
    /// Encrypts binary <paramref name="plaintext"/> with the current key and a fresh random nonce.
    /// A <see cref="byte"/> array converts implicitly. The output format is the same as for text, which is
    /// encrypted as its UTF-8 bytes, so <see cref="DecryptBytes"/> can read text payloads and vice versa.
    /// </summary>
    /// <param name="plaintext">The bytes to encrypt. May be empty.</param>
    /// <returns>A self-describing, URL-safe string that embeds the key ID, nonce, and authentication tag.</returns>
    string Encrypt(ReadOnlySpan<byte> plaintext);

    /// <summary>
    /// Encrypts binary <paramref name="plaintext"/> with the current key, binding it to <paramref name="associatedData"/>.
    /// </summary>
    /// <param name="plaintext">The bytes to encrypt. May be empty.</param>
    /// <param name="associatedData">Authenticated context; see <see cref="Encrypt(string, string?)"/>.</param>
    /// <returns>A self-describing, URL-safe string that embeds the key ID, nonce, and authentication tag.</returns>
    string Encrypt(ReadOnlySpan<byte> plaintext, string? associatedData);

    /// <summary>
    /// Decrypts a value to its raw bytes.
    /// </summary>
    /// <param name="payload">The encrypted string.</param>
    /// <param name="associatedData">The same context that was supplied to encrypt, if any.</param>
    /// <returns>The original bytes. The caller owns the array and may zero it when done.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">
    /// The payload is malformed, was tampered with, uses an unknown key, or the associated data does not match.
    /// </exception>
    byte[] DecryptBytes(string payload, string? associatedData = null);

    /// <summary>
    /// Attempts to decrypt a value to its raw bytes.
    /// </summary>
    /// <param name="payload">The encrypted string.</param>
    /// <param name="plaintext">The original bytes when decryption succeeds; otherwise <see langword="null"/>.</param>
    /// <param name="associatedData">The same context that was supplied to encrypt, if any.</param>
    /// <returns><see langword="true"/> if decryption and authentication succeeded.</returns>
    bool TryDecryptBytes(string payload, out byte[]? plaintext, string? associatedData = null);

    /// <summary>
    /// Determines whether <paramref name="payload"/> was encrypted with a key other than the current one and
    /// should be re-encrypted.
    /// </summary>
    /// <param name="payload">The encrypted string.</param>
    /// <returns><see langword="true"/> if the payload is malformed or not encrypted with the current key.</returns>
    bool NeedsReEncryption(string payload);
}
