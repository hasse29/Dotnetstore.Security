using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// A thread-safe, in-process <see cref="IRefreshTokenStore"/> for tests and single-instance development setups.
/// Tokens are lost on restart and never removed, so do not use it in production.
/// </summary>
public sealed class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly Lock _lock = new();
    private readonly Dictionary<string, StoredRefreshToken> _tokens = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask SaveAsync(StoredRefreshToken token, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(token);

        lock (_lock)
        {
            _tokens[token.Hash] = token;
        }

        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public ValueTask<StoredRefreshToken?> FindAsync(string hash, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            return ValueTask.FromResult(_tokens.GetValueOrDefault(hash));
        }
    }

    /// <inheritdoc />
    public ValueTask<bool> TryMarkUsedAsync(string hash, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            if (!_tokens.TryGetValue(hash, out var token) || token.IsUsed)
            {
                return ValueTask.FromResult(false);
            }

            _tokens[hash] = token with { IsUsed = true };
            return ValueTask.FromResult(true);
        }
    }

    /// <inheritdoc />
    public ValueTask RevokeFamilyAsync(string familyId, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            foreach (var (hash, token) in _tokens.ToArray())
            {
                if (token.FamilyId == familyId)
                {
                    _tokens[hash] = token with { IsRevoked = true };
                }
            }
        }

        return ValueTask.CompletedTask;
    }
}
