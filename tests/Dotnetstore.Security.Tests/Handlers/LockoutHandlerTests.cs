using Dotnetstore.Security.Extensions;
using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Dotnetstore.Security.Tests.Handlers;

public class LockoutHandlerTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Start);
    private readonly InMemoryLockoutStore _store;
    private readonly LockoutHandler _handler;

    public LockoutHandlerTests()
    {
        _store = new InMemoryLockoutStore(_time);
        _handler = new LockoutHandler(_store, new LockoutOptions(), _time);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task NewKey_IsNotLockedWithFullAttempts()
    {
        var status = await _handler.GetStatusAsync("login:ann", Ct);

        Assert.False(status.IsLockedOut);
        Assert.Equal(5, status.RemainingAttempts);
        Assert.Null(status.LockedUntil);
    }

    [Fact]
    public async Task Failures_CountDownThenLockOut()
    {
        for (var expected = 4; expected >= 1; expected--)
        {
            var status = await _handler.RecordFailureAsync("login:ann", Ct);
            Assert.False(status.IsLockedOut);
            Assert.Equal(expected, status.RemainingAttempts);
        }

        var locked = await _handler.RecordFailureAsync("login:ann", Ct);

        Assert.True(locked.IsLockedOut);
        Assert.Equal(0, locked.RemainingAttempts);
        Assert.Equal(Start.AddMinutes(15), locked.LockedUntil);
        Assert.True((await _handler.GetStatusAsync("login:ann", Ct)).IsLockedOut);
    }

    [Fact]
    public async Task Lockout_EndsAfterDuration_AndCountersStartOver()
    {
        for (var i = 0; i < 5; i++)
        {
            await _handler.RecordFailureAsync("login:ann", Ct);
        }

        _time.Advance(TimeSpan.FromMinutes(16));
        var after = await _handler.GetStatusAsync("login:ann", Ct);
        var next = await _handler.RecordFailureAsync("login:ann", Ct);

        Assert.False(after.IsLockedOut);
        Assert.Equal(5, after.RemainingAttempts);
        Assert.False(next.IsLockedOut);
        Assert.Equal(4, next.RemainingAttempts);
    }

    [Fact]
    public async Task FurtherFailuresWhileLocked_DoNotExtendTheLockout()
    {
        for (var i = 0; i < 5; i++)
        {
            await _handler.RecordFailureAsync("login:ann", Ct);
        }

        _time.Advance(TimeSpan.FromMinutes(10));
        var status = await _handler.RecordFailureAsync("login:ann", Ct);

        Assert.True(status.IsLockedOut);
        Assert.Equal(Start.AddMinutes(15), status.LockedUntil);
    }

    [Fact]
    public async Task OldFailures_FallOutOfTheWindow()
    {
        for (var i = 0; i < 4; i++)
        {
            await _handler.RecordFailureAsync("login:ann", Ct);
        }

        _time.Advance(TimeSpan.FromMinutes(20));
        var status = await _handler.RecordFailureAsync("login:ann", Ct);

        Assert.False(status.IsLockedOut);
        Assert.Equal(4, status.RemainingAttempts);
    }

    [Fact]
    public async Task Reset_ClearsFailures()
    {
        for (var i = 0; i < 3; i++)
        {
            await _handler.RecordFailureAsync("login:ann", Ct);
        }

        await _handler.ResetAsync("login:ann", Ct);

        Assert.Equal(5, (await _handler.GetStatusAsync("login:ann", Ct)).RemainingAttempts);
    }

    [Fact]
    public async Task Keys_AreIndependent()
    {
        for (var i = 0; i < 5; i++)
        {
            await _handler.RecordFailureAsync("login:ann", Ct);
        }

        Assert.True((await _handler.GetStatusAsync("login:ann", Ct)).IsLockedOut);
        Assert.False((await _handler.GetStatusAsync("login:bob", Ct)).IsLockedOut);
    }

    [Fact]
    public async Task ConcurrentFailures_AreAllCounted()
    {
        var handler = new LockoutHandler(_store, new LockoutOptions { MaxFailedAttempts = 1000 }, _time);

        await Task.WhenAll(Enumerable.Range(0, 200).Select(_ => Task.Run(() => handler.RecordFailureAsync("k", Ct), Ct)));

        Assert.Equal(800, (await handler.GetStatusAsync("k", Ct)).RemainingAttempts);
    }

    [Fact]
    public async Task ExpiredEntries_ArePrunedFromTheStore()
    {
        var store = new InMemoryLockoutStore(_time);
        var handler = new LockoutHandler(store, new LockoutOptions(), _time);

        for (var i = 0; i < 10_000; i++)
        {
            await handler.RecordFailureAsync($"k{i}", Ct);
        }

        _time.Advance(TimeSpan.FromHours(1));
        await handler.RecordFailureAsync("fresh", Ct);

        Assert.Null(await store.GetAsync("k0", Ct));
        Assert.NotNull(await store.GetAsync("fresh", Ct));
    }

    [Fact]
    public async Task EmptyKey_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _handler.GetStatusAsync("", Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => _handler.RecordFailureAsync("", Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => _handler.ResetAsync("", Ct));
    }

    [Fact]
    public void InvalidOptions_Throw()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new LockoutHandler(_store, new LockoutOptions { MaxFailedAttempts = 0 }, _time));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new LockoutHandler(_store, new LockoutOptions { LockoutDuration = TimeSpan.Zero }, _time));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new LockoutHandler(_store, new LockoutOptions { FailureWindow = TimeSpan.Zero }, _time));
    }

    [Fact]
    public async Task AddLockout_RegistersHandlerWithDefaultStore_AndValidatesAtStartup()
    {
        using var provider = new ServiceCollection().AddLockout(o => o.MaxFailedAttempts = 2).BuildServiceProvider();

        provider.GetRequiredService<IStartupValidator>().Validate();
        var handler = provider.GetRequiredService<ILockoutHandler>();
        await handler.RecordFailureAsync("k", Ct);

        Assert.True((await handler.RecordFailureAsync("k", Ct)).IsLockedOut);
        Assert.IsType<InMemoryLockoutStore>(provider.GetRequiredService<ILockoutStore>());

        using var broken = new ServiceCollection().AddLockout(o => o.MaxFailedAttempts = 0).BuildServiceProvider();
        Assert.Throws<OptionsValidationException>(() => broken.GetRequiredService<IStartupValidator>().Validate());
    }

    [Fact]
    public void AddLockoutWithStore_UsesTheCustomStore()
    {
        using var provider = new ServiceCollection().AddLockout<CustomStore>().BuildServiceProvider();

        Assert.IsType<CustomStore>(provider.GetRequiredService<ILockoutStore>());
    }

    private sealed class CustomStore : ILockoutStore
    {
        public ValueTask<LockoutState?> GetAsync(string key, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<LockoutState?>(null);

        public ValueTask<LockoutState> UpdateAsync(
            string key,
            Func<LockoutState?, LockoutState> update,
            CancellationToken cancellationToken = default) => ValueTask.FromResult(update(null));

        public ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;
    }
}
