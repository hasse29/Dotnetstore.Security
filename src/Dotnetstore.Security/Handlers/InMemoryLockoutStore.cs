using Dotnetstore.Security.Models;

namespace Dotnetstore.Security.Handlers;

/// <summary>
/// A thread-safe, in-process <see cref="ILockoutStore"/>. State is lost on restart and is not shared between
/// instances of an app, so with several instances an attacker gets the full limit on each. Expired entries are
/// removed as new ones are added.
/// </summary>
public sealed class InMemoryLockoutStore(TimeProvider timeProvider) : ILockoutStore
{
    private const int PruneThreshold = 10_000;

    private readonly Lock _lock = new();
    private readonly Dictionary<string, LockoutState> _states = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public ValueTask<LockoutState?> GetAsync(string key, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            return ValueTask.FromResult(_states.GetValueOrDefault(key));
        }
    }

    /// <inheritdoc />
    public ValueTask<LockoutState> UpdateAsync(
        string key,
        Func<LockoutState?, LockoutState> update,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(update);

        lock (_lock)
        {
            if (_states.Count >= PruneThreshold)
            {
                Prune();
            }

            var next = update(_states.GetValueOrDefault(key));
            _states[key] = next;
            return ValueTask.FromResult(next);
        }
    }

    /// <inheritdoc />
    public ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            _states.Remove(key);
        }

        return ValueTask.CompletedTask;
    }

    private void Prune()
    {
        var now = timeProvider.GetUtcNow();
        foreach (var (key, state) in _states.ToArray())
        {
            if (state.ExpiresAt <= now)
            {
                _states.Remove(key);
            }
        }
    }
}
