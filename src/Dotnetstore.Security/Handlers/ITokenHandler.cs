using System.Security.Claims;
using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// Creates and validates JWT access tokens and creates opaque refresh tokens.
/// </summary>
public interface ITokenHandler
{
    /// <summary>
    /// Creates a signed access token.
    /// </summary>
    /// <param name="subject">The user or principal identifier, written to the <c>sub</c> claim.</param>
    /// <param name="claims">
    /// Additional claims, for example <c>role</c> or <c>email</c>. Several claims of the same type become a JSON array.
    /// </param>
    /// <returns>The token and its expiry.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="subject"/> is empty, or <paramref name="claims"/> contains a registered claim
    /// (<c>sub</c>, <c>iss</c>, <c>aud</c>, <c>exp</c>, <c>nbf</c>, <c>iat</c>, <c>jti</c>) that the handler sets itself.
    /// </exception>
    AccessToken CreateAccessToken(string subject, IEnumerable<Claim>? claims = null);

    /// <summary>
    /// Validates the signature, algorithm, issuer, audience, and lifetime of an access token.
    /// </summary>
    /// <param name="token">The compact serialized JWT.</param>
    /// <returns>
    /// The token's claims as a principal, using the raw JWT claim names (<c>sub</c>, <c>role</c>, ...),
    /// or <see langword="null"/> if the token is invalid or expired.
    /// </returns>
    Task<ClaimsPrincipal?> ValidateAccessTokenAsync(string token);

    /// <summary>
    /// Creates a new random refresh token.
    /// </summary>
    /// <returns>The token for the client, the hash to store, and the expiry.</returns>
    RefreshToken CreateRefreshToken();

    /// <summary>
    /// Computes the storable hash of a refresh token presented by a client, for looking up its stored record.
    /// </summary>
    /// <param name="refreshToken">The refresh token value.</param>
    /// <returns>The hash, equal to <see cref="RefreshToken.Hash"/> for the token it was created from.</returns>
    string HashRefreshToken(string refreshToken);

    /// <summary>
    /// Checks a presented refresh token against a stored hash in constant time.
    /// </summary>
    /// <param name="refreshToken">The refresh token value presented by the client.</param>
    /// <param name="storedHash">The hash stored when the token was created.</param>
    /// <returns><see langword="true"/> if they match. Expiry and revocation must still be checked by the caller.</returns>
    bool VerifyRefreshToken(string refreshToken, string storedHash);
}
