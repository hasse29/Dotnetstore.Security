using System.Buffers.Text;
using System.Security.Cryptography;
using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

internal sealed class RefreshTokenService(
    ITokenHandler tokenHandler,
    IRefreshTokenStore store,
    TimeProvider timeProvider) : IRefreshTokenService
{
    public async Task<RefreshToken> IssueAsync(string subject, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        var familyId = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16));
        return await CreateAndSaveAsync(subject, familyId, cancellationToken).ConfigureAwait(false);
    }

    public async Task<RefreshResult> RotateAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(refreshToken))
        {
            return new RefreshResult(RefreshStatus.Invalid);
        }

        var hash = tokenHandler.HashRefreshToken(refreshToken);
        var stored = await store.FindAsync(hash, cancellationToken).ConfigureAwait(false);

        if (stored is null)
        {
            return new RefreshResult(RefreshStatus.Invalid);
        }

        if (stored.IsRevoked)
        {
            return new RefreshResult(RefreshStatus.Revoked);
        }

        if (stored.IsUsed)
        {
            return await RefuseAsReuseAsync(stored, cancellationToken).ConfigureAwait(false);
        }

        if (stored.ExpiresAt <= timeProvider.GetUtcNow())
        {
            return new RefreshResult(RefreshStatus.Expired);
        }

        // Another request may have exchanged the same token since we read it.
        if (!await store.TryMarkUsedAsync(hash, cancellationToken).ConfigureAwait(false))
        {
            return await RefuseAsReuseAsync(stored, cancellationToken).ConfigureAwait(false);
        }

        var next = await CreateAndSaveAsync(stored.Subject, stored.FamilyId, cancellationToken).ConfigureAwait(false);
        return new RefreshResult(RefreshStatus.Success, stored.Subject, next);
    }

    public async Task RevokeAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(refreshToken))
        {
            return;
        }

        var stored = await store
            .FindAsync(tokenHandler.HashRefreshToken(refreshToken), cancellationToken)
            .ConfigureAwait(false);

        if (stored is not null)
        {
            await store.RevokeFamilyAsync(stored.FamilyId, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<RefreshResult> RefuseAsReuseAsync(StoredRefreshToken stored, CancellationToken cancellationToken)
    {
        await store.RevokeFamilyAsync(stored.FamilyId, cancellationToken).ConfigureAwait(false);
        return new RefreshResult(RefreshStatus.Reused);
    }

    private async Task<RefreshToken> CreateAndSaveAsync(
        string subject,
        string familyId,
        CancellationToken cancellationToken)
    {
        var token = tokenHandler.CreateRefreshToken();
        await store
            .SaveAsync(new StoredRefreshToken(token.Hash, subject, familyId, token.ExpiresAt), cancellationToken)
            .ConfigureAwait(false);
        return token;
    }
}
