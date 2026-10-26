using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// Issues refresh tokens and exchanges them for new ones with rotation and reuse detection: every token can be
/// used once, and presenting a used token revokes the whole chain it belongs to.
/// </summary>
public interface IRefreshTokenService
{
    /// <summary>
    /// Starts a new token family for <paramref name="subject"/>, for example at login, and saves the first token.
    /// </summary>
    /// <param name="subject">The user or principal identifier.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The token to give to the client. Its value cannot be recovered later.</returns>
    Task<RefreshToken> IssueAsync(string subject, CancellationToken cancellationToken = default);

    /// <summary>
    /// Exchanges a presented refresh token for a new one in the same family.
    /// </summary>
    /// <param name="refreshToken">The token value presented by the client.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// On success, the subject and the replacement token, after which the caller should create a new access token.
    /// Otherwise the reason it was refused. Respond to every refusal with the same generic "sign in again" error.
    /// </returns>
    Task<RefreshResult> RotateAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes the family of a presented token, for example at logout. Unknown tokens are ignored.
    /// </summary>
    /// <param name="refreshToken">The token value presented by the client.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task that completes when the family is revoked.</returns>
    Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default);
}
