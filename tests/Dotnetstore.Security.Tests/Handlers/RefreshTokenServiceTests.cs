using System.Security.Cryptography;
using Dotnetstore.Security.Extensions;
using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dotnetstore.Security.Tests.Handlers;

public class RefreshTokenServiceTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private readonly FakeTimeProvider _time = new(Start);
    private readonly InMemoryRefreshTokenStore _store = new();
    private readonly RefreshTokenService _service;

    public RefreshTokenServiceTests()
    {
        var options = new TokenOptions { Issuer = "i", Audience = "a" };
        options.SigningKeys["k1"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        options.CurrentSigningKeyId = "k1";
        _service = new RefreshTokenService(new TokenHandler(options, _time), _store, _time);
    }

    [Fact]
    public async Task Issue_StoresHashedTokenForSubject()
    {
        var token = await _service.IssueAsync("user-1", TestContext.Current.CancellationToken);

        var stored = await _store.FindAsync(token.Hash, TestContext.Current.CancellationToken);

        Assert.NotNull(stored);
        Assert.Equal("user-1", stored.Subject);
        Assert.Equal(token.ExpiresAt, stored.ExpiresAt);
        Assert.False(stored.IsUsed);
        Assert.False(stored.IsRevoked);
        Assert.NotEqual(token.Value, stored.Hash);
    }

    [Fact]
    public async Task Rotate_ValidToken_ReturnsSubjectAndNewTokenInSameFamily()
    {
        var first = await _service.IssueAsync("user-1", TestContext.Current.CancellationToken);

        var result = await _service.RotateAsync(first.Value, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
        Assert.Equal("user-1", result.Subject);
        Assert.NotNull(result.NewToken);
        Assert.NotEqual(first.Value, result.NewToken.Value);

        var oldStored = await _store.FindAsync(first.Hash, TestContext.Current.CancellationToken);
        var newStored = await _store.FindAsync(result.NewToken.Hash, TestContext.Current.CancellationToken);
        Assert.True(oldStored!.IsUsed);
        Assert.Equal(oldStored.FamilyId, newStored!.FamilyId);
    }

    [Fact]
    public async Task Rotate_ChainOfTokens_KeepsWorking()
    {
        var token = await _service.IssueAsync("user-1", TestContext.Current.CancellationToken);

        for (var i = 0; i < 3; i++)
        {
            var result = await _service.RotateAsync(token.Value, TestContext.Current.CancellationToken);
            Assert.True(result.IsSuccess);
            token = result.NewToken!;
        }
    }

    [Fact]
    public async Task Rotate_ReusedToken_RevokesWholeFamily()
    {
        var first = await _service.IssueAsync("user-1", TestContext.Current.CancellationToken);
        var second = (await _service.RotateAsync(first.Value, TestContext.Current.CancellationToken)).NewToken!;

        var replay = await _service.RotateAsync(first.Value, TestContext.Current.CancellationToken);
        var legitimateNext = await _service.RotateAsync(second.Value, TestContext.Current.CancellationToken);

        Assert.Equal(RefreshStatus.Reused, replay.Status);
        Assert.Null(replay.NewToken);
        Assert.Equal(RefreshStatus.Revoked, legitimateNext.Status);
    }

    [Fact]
    public async Task Rotate_ReuseInOneFamily_DoesNotAffectOtherFamilies()
    {
        var mine = await _service.IssueAsync("user-1", TestContext.Current.CancellationToken);
        var other = await _service.IssueAsync("user-1", TestContext.Current.CancellationToken);
        await _service.RotateAsync(mine.Value, TestContext.Current.CancellationToken);
        await _service.RotateAsync(mine.Value, TestContext.Current.CancellationToken);

        var result = await _service.RotateAsync(other.Value, TestContext.Current.CancellationToken);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public async Task Rotate_ConcurrentExchangesOfSameToken_OnlyOneSucceeds()
    {
        var token = await _service.IssueAsync("user-1", TestContext.Current.CancellationToken);

        var results = await Task.WhenAll(Enumerable.Range(0, 8)
            .Select(_ => Task.Run(() => _service.RotateAsync(token.Value, TestContext.Current.CancellationToken), TestContext.Current.CancellationToken)));

        Assert.Single(results, r => r.IsSuccess);
    }

    [Fact]
    public async Task Rotate_ExpiredToken_IsRefused()
    {
        var token = await _service.IssueAsync("user-1", TestContext.Current.CancellationToken);

        _time.Advance(TimeSpan.FromDays(8));
        var result = await _service.RotateAsync(token.Value, TestContext.Current.CancellationToken);

        Assert.Equal(RefreshStatus.Expired, result.Status);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-real-token")]
    public async Task Rotate_UnknownToken_IsInvalid(string value)
    {
        var result = await _service.RotateAsync(value, TestContext.Current.CancellationToken);

        Assert.Equal(RefreshStatus.Invalid, result.Status);
    }

    [Fact]
    public async Task Revoke_RevokesFamily_AndIgnoresUnknownTokens()
    {
        var first = await _service.IssueAsync("user-1", TestContext.Current.CancellationToken);
        var second = (await _service.RotateAsync(first.Value, TestContext.Current.CancellationToken)).NewToken!;

        await _service.RevokeAsync(second.Value, TestContext.Current.CancellationToken);
        await _service.RevokeAsync("unknown", TestContext.Current.CancellationToken);
        await _service.RevokeAsync("", TestContext.Current.CancellationToken);

        var result = await _service.RotateAsync(second.Value, TestContext.Current.CancellationToken);
        Assert.Equal(RefreshStatus.Revoked, result.Status);
    }

    [Fact]
    public async Task Issue_EmptySubject_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() => _service.IssueAsync(" ", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AddRefreshTokenRotation_ResolvesServiceWithRegisteredStore()
    {
        var options = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        using var provider = new ServiceCollection()
            .AddTokens(o =>
            {
                o.Issuer = "i";
                o.Audience = "a";
                o.SigningKeys["k1"] = options;
                o.CurrentSigningKeyId = "k1";
            })
            .AddRefreshTokenRotation<InMemoryRefreshTokenStore>()
            .BuildServiceProvider(validateScopes: true);

        using var scope = provider.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<IRefreshTokenService>();
        var token = await service.IssueAsync("user-1", TestContext.Current.CancellationToken);

        Assert.True((await service.RotateAsync(token.Value, TestContext.Current.CancellationToken)).IsSuccess);
    }
}
