using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// Persistence for refresh tokens. Implement this over your database or distributed cache.
/// </summary>
public interface IRefreshTokenStore
{
    /// <summary>Saves a new token.</summary>
    /// <param name="token">The token to save.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task that completes when the token is saved.</returns>
    ValueTask SaveAsync(StoredRefreshToken token, CancellationToken cancellationToken = default);

    /// <summary>Finds a token by its hash.</summary>
    /// <param name="hash">The token hash.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>The stored token, or <see langword="null"/> if none exists.</returns>
    ValueTask<StoredRefreshToken?> FindAsync(string hash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Marks a token as used, atomically. Two concurrent exchanges of the same token must not both succeed,
    /// so use a conditional update such as <c>UPDATE ... SET IsUsed = 1 WHERE Hash = @hash AND IsUsed = 0</c>.
    /// </summary>
    /// <param name="hash">The token hash.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>
    /// <see langword="true"/> if this call changed the token from unused to used;
    /// <see langword="false"/> if it was already used or does not exist.
    /// </returns>
    ValueTask<bool> TryMarkUsedAsync(string hash, CancellationToken cancellationToken = default);

    /// <summary>Revokes every token in a family, so each reports <see cref="StoredRefreshToken.IsRevoked"/>.</summary>
    /// <param name="familyId">The family to revoke.</param>
    /// <param name="cancellationToken">A token to cancel the operation.</param>
    /// <returns>A task that completes when the family is revoked.</returns>
    ValueTask RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default);
}
