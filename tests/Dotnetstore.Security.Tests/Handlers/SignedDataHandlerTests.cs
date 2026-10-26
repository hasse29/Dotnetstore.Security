using System.Security.Cryptography;
using Dotnetstore.Security.Extensions;
using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Dotnetstore.Security.Tests.Handlers;

public class SignedDataHandlerTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static string NewKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static SignedDataOptions Options(string currentId, params (string Id, string Value)[] keys)
    {
        var options = new SignedDataOptions { CurrentKeyId = currentId };
        foreach (var (id, value) in keys)
        {
            options.Keys[id] = value;
        }

        return options;
    }

    private static SignedDataHandler CreateHandler(FakeTimeProvider time, string key) =>
        new(Options("k1", ("k1", key)), time);

    [Fact]
    public void SignThenValidate_ReturnsPayload()
    {
        var handler = CreateHandler(new FakeTimeProvider(Start), NewKey());

        var token = handler.Sign("user-42", "email-verification");

        Assert.True(handler.TryValidate(token, "email-verification", out var payload));
        Assert.Equal("user-42", payload);
    }

    [Fact]
    public void Sign_ProducesUrlSafeVersionedFormat()
    {
        var token = CreateHandler(new FakeTimeProvider(Start), NewKey()).Sign("a b/c+d", "p");
        var parts = token.Split('.');

        Assert.Equal(5, parts.Length);
        Assert.Equal("dsd1", parts[0]);
        Assert.Equal("k1", parts[1]);
        Assert.Equal(Start.AddHours(1).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), parts[2]);
        Assert.All(token, c => Assert.True(char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_'));
    }

    [Fact]
    public void Validate_WrongPurpose_IsRejected()
    {
        var handler = CreateHandler(new FakeTimeProvider(Start), NewKey());
        var token = handler.Sign("user-42", "email-verification");

        Assert.False(handler.TryValidate(token, "password-reset", out var payload));
        Assert.Null(payload);
    }

    [Fact]
    public void Validate_Expired_IsRejected()
    {
        var time = new FakeTimeProvider(Start);
        var handler = CreateHandler(time, NewKey());
        var token = handler.Sign("user-42", "p", TimeSpan.FromMinutes(10));

        time.Advance(TimeSpan.FromMinutes(9));
        Assert.True(handler.TryValidate(token, "p", out _));

        time.Advance(TimeSpan.FromMinutes(2));
        Assert.False(handler.TryValidate(token, "p", out _));
    }

    [Fact]
    public void Validate_TamperedPayloadExpiryOrMac_IsRejected()
    {
        var time = new FakeTimeProvider(Start);
        var handler = CreateHandler(time, NewKey());
        var admin = handler.Sign("admin", "p").Split('.');

        var forgedPayload = handler.Sign("user", "p").Split('.');
        forgedPayload[3] = admin[3];

        var extendedExpiry = handler.Sign("user", "p").Split('.');
        extendedExpiry[2] = (long.Parse(extendedExpiry[2], System.Globalization.CultureInfo.InvariantCulture) + 86_400)
            .ToString(System.Globalization.CultureInfo.InvariantCulture);

        Assert.False(handler.TryValidate(string.Join('.', forgedPayload), "p", out _));
        Assert.False(handler.TryValidate(string.Join('.', extendedExpiry), "p", out _));
    }

    [Fact]
    public void Validate_DifferentKey_IsRejected()
    {
        var time = new FakeTimeProvider(Start);
        var token = CreateHandler(time, NewKey()).Sign("user", "p");

        Assert.False(CreateHandler(time, NewKey()).TryValidate(token, "p", out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("dsd1.k1.1.a.b")]
    [InlineData("dsd2.k1.99999999999.YQ.YQ")]
    [InlineData("dsd1.unknown.99999999999.YQ.YQ")]
    [InlineData("dsd1.k1.notanumber.YQ.YQ")]
    [InlineData("dsd1.k1.99999999999.!!.!!")]
    public void Validate_MalformedValues_ReturnFalseWithoutThrowing(string token)
    {
        Assert.False(CreateHandler(new FakeTimeProvider(Start), NewKey()).TryValidate(token, "p", out _));
    }

    [Fact]
    public void KeyRotation_OldValuesStillValidate()
    {
        var time = new FakeTimeProvider(Start);
        var oldKey = NewKey();
        var oldToken = CreateHandler(time, oldKey).Sign("user", "p");

        var rotated = new SignedDataHandler(Options("k2", ("k1", oldKey), ("k2", NewKey())), time);
        var newToken = rotated.Sign("user", "p");

        Assert.True(rotated.TryValidate(oldToken, "p", out _));
        Assert.StartsWith("dsd1.k2.", newToken, StringComparison.Ordinal);
        Assert.True(rotated.TryValidate(newToken, "p", out _));
    }

    [Fact]
    public void Sign_InvalidArguments_Throw()
    {
        var handler = CreateHandler(new FakeTimeProvider(Start), NewKey());

        Assert.Throws<ArgumentNullException>(() => handler.Sign(null!, "p"));
        Assert.Throws<ArgumentException>(() => handler.Sign("x", ""));
        Assert.Throws<ArgumentException>(() => handler.Sign("x", "a\nb"));
        Assert.Throws<ArgumentOutOfRangeException>(() => handler.Sign("x", "p", TimeSpan.Zero));
    }

    [Fact]
    public void Sign_EmptyAndUnicodePayloads_RoundTrip()
    {
        var handler = CreateHandler(new FakeTimeProvider(Start), NewKey());

        foreach (var payload in new[] { "", "pässwörd ✓ 日本語" })
        {
            Assert.True(handler.TryValidate(handler.Sign(payload, "p"), "p", out var result));
            Assert.Equal(payload, result);
        }
    }

    [Fact]
    public void InvalidConfiguration_Throws()
    {
        var time = new FakeTimeProvider(Start);

        Assert.Throws<ArgumentException>(() => new SignedDataHandler(Options("k1"), time));
        Assert.Throws<ArgumentException>(() => new SignedDataHandler(Options("k2", ("k1", NewKey())), time));
        Assert.Throws<ArgumentException>(() => new SignedDataHandler(Options("k1", ("k1", "AAAA")), time));
        Assert.Throws<ArgumentException>(() => new SignedDataHandler(Options("bad.id", ("bad.id", NewKey())), time));

        var badLifetime = Options("k1", ("k1", NewKey()));
        badLifetime.DefaultLifetime = TimeSpan.Zero;
        Assert.Throws<ArgumentOutOfRangeException>(() => new SignedDataHandler(badLifetime, time));
    }

    [Fact]
    public void AddSignedData_ResolvesConfiguredSingletonAndValidatesAtStartup()
    {
        var key = NewKey();
        using var provider = new ServiceCollection()
            .AddSignedData(o =>
            {
                o.Keys["k1"] = key;
                o.CurrentKeyId = "k1";
            })
            .BuildServiceProvider();

        provider.GetRequiredService<IStartupValidator>().Validate();
        var handler = provider.GetRequiredService<ISignedDataHandler>();

        Assert.Same(handler, provider.GetRequiredService<ISignedDataHandler>());
        Assert.True(handler.TryValidate(handler.Sign("x", "p"), "p", out _));

        using var broken = new ServiceCollection().AddSignedData().BuildServiceProvider();
        Assert.Throws<OptionsValidationException>(() => broken.GetRequiredService<IStartupValidator>().Validate());
    }
}
