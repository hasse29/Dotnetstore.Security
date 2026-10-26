using Dotnetstore.Security.Models;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.Handlers;

internal sealed class LockoutHandler : ILockoutHandler
{
    private readonly ILockoutStore _store;
    private readonly TimeProvider _timeProvider;
    private readonly LockoutOptions _options;

    public LockoutHandler(ILockoutStore store, IOptions<LockoutOptions> options, TimeProvider timeProvider)
        : this(store, options.Value, timeProvider)
    {
    }

    public LockoutHandler(ILockoutStore store, LockoutOptions options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        options.Validate();
        _store = store;
        _timeProvider = timeProvider;
        _options = new LockoutOptions
        {
            MaxFailedAttempts = options.MaxFailedAttempts,
            LockoutDuration = options.LockoutDuration,
            FailureWindow = options.FailureWindow,
        };
    }

    public async Task<LockoutStatus> GetStatusAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        var state = await _store.GetAsync(key, cancellationToken).ConfigureAwait(false);
        return ToStatus(state, _timeProvider.GetUtcNow());
    }

    public async Task<LockoutStatus> RecordFailureAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        var now = _timeProvider.GetUtcNow();
        var state = await _store.UpdateAsync(key, current => Next(current, now), cancellationToken).ConfigureAwait(false);
        return ToStatus(state, now);
    }

    public async Task ResetAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);

        await _store.RemoveAsync(key, cancellationToken).ConfigureAwait(false);
    }

    private LockoutState Next(LockoutState? current, DateTimeOffset now)
    {
        // A lockout in force is not extended by further failures.
        if (current?.LockedUntil > now)
        {
            return current;
        }

        var isFresh = current is null
            || current.LockedUntil is not null
            || now - current.WindowStart >= _options.FailureWindow;

        var windowStart = isFresh ? now : current!.WindowStart;
        var count = isFresh ? 1 : current!.FailureCount + 1;
        DateTimeOffset? lockedUntil = count >= _options.MaxFailedAttempts ? now + _options.LockoutDuration : null;
        var windowEnd = windowStart + _options.FailureWindow;

        return new LockoutState(count, windowStart, lockedUntil, lockedUntil is { } until && until > windowEnd ? until : windowEnd);
    }

    private LockoutStatus ToStatus(LockoutState? state, DateTimeOffset now)
    {
        if (state is null)
        {
            return new LockoutStatus(false, _options.MaxFailedAttempts, null);
        }

        if (state.LockedUntil > now)
        {
            return new LockoutStatus(true, 0, state.LockedUntil);
        }

        var expired = state.LockedUntil is not null || now - state.WindowStart >= _options.FailureWindow;
        return expired
            ? new LockoutStatus(false, _options.MaxFailedAttempts, null)
            : new LockoutStatus(false, Math.Max(0, _options.MaxFailedAttempts - state.FailureCount), null);
    }
}
