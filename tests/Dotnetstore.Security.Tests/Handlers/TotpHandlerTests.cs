using System.Text;
using Dotnetstore.Security.Extensions;
using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Internal;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Dotnetstore.Security.Tests.Handlers;

public class TotpHandlerTests
{
    // RFC 6238 appendix B uses the ASCII secret "12345678901234567890" with HMAC-SHA1.
    private static readonly string RfcSecret = Base32.Encode(Encoding.ASCII.GetBytes("12345678901234567890"));

    private static readonly DateTimeOffset Start = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static TotpHandler CreateHandler(FakeTimeProvider? time = null, Action<TotpOptions>? configure = null)
    {
        var options = new TotpOptions();
        configure?.Invoke(options);
        return new TotpHandler(options, time ?? new FakeTimeProvider(Start));
    }

    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    public void GenerateCode_MatchesRfc6238EightDigitVectors(long unixSeconds, string expected)
    {
        var handler = CreateHandler(configure: o => o.Digits = 8);

        Assert.Equal(expected, handler.GenerateCode(RfcSecret, DateTimeOffset.FromUnixTimeSeconds(unixSeconds)));
    }

    [Fact]
    public void GenerateCode_SixDigitsAreTheLastSixOfTheEightDigitVector()
    {
        var handler = CreateHandler();

        Assert.Equal("287082", handler.GenerateCode(RfcSecret, DateTimeOffset.FromUnixTimeSeconds(59)));
    }

    [Fact]
    public void Base32_RoundTripsAndMatchesRfc4648Vectors()
    {
        Assert.Equal("MZXW6YTBOI", Base32.Encode("foobar"u8));
        Assert.Equal("MZXW6", Base32.Encode("foo"u8));
        Assert.True(Base32.TryDecode("mzxw 6ytb-oi==", out var decoded));
        Assert.Equal("foobar", Encoding.ASCII.GetString(decoded));
        Assert.False(Base32.TryDecode("MZXW1", out _));
        Assert.False(Base32.TryDecode("", out _));
    }

    [Fact]
    public void GenerateSecret_IsValidBase32OfRequestedSize()
    {
        var handler = CreateHandler();
        var secret = handler.GenerateSecret();

        Assert.True(Base32.TryDecode(secret, out var bytes));
        Assert.Equal(20, bytes.Length);
        Assert.NotEqual(secret, handler.GenerateSecret());
        Assert.Throws<ArgumentOutOfRangeException>(() => handler.GenerateSecret(8));
        Assert.Throws<ArgumentOutOfRangeException>(() => handler.GenerateSecret(100));
    }

    [Fact]
    public void Verify_CurrentCode_Succeeds()
    {
        var time = new FakeTimeProvider(Start);
        var handler = CreateHandler(time);
        var code = handler.GenerateCode(RfcSecret);

        Assert.True(handler.Verify(RfcSecret, code, out var step));
        Assert.Equal(Start.ToUnixTimeSeconds() / 30, step);
    }

    [Fact]
    public void Verify_AcceptsCodesWithinDriftAndIgnoresSpaces()
    {
        var time = new FakeTimeProvider(Start);
        var handler = CreateHandler(time);
        var previous = handler.GenerateCode(RfcSecret, Start.AddSeconds(-30));
        var next = handler.GenerateCode(RfcSecret, Start.AddSeconds(30));
        var tooOld = handler.GenerateCode(RfcSecret, Start.AddSeconds(-90));

        Assert.True(handler.Verify(RfcSecret, previous, out _));
        Assert.True(handler.Verify(RfcSecret, next, out _));
        Assert.True(handler.Verify(RfcSecret, previous.Insert(3, " "), out _));
        Assert.False(handler.Verify(RfcSecret, tooOld, out _));
    }

    [Fact]
    public void Verify_ReplayedStep_IsRejected()
    {
        var handler = CreateHandler();
        var code = handler.GenerateCode(RfcSecret);

        Assert.True(handler.Verify(RfcSecret, code, out var step));
        Assert.False(handler.Verify(RfcSecret, code, out _, lastUsedTimeStep: step));
        Assert.True(handler.Verify(RfcSecret, code, out _, lastUsedTimeStep: step - 1));
    }

    [Fact]
    public void Verify_CodeExpiresAsTimePasses()
    {
        var time = new FakeTimeProvider(Start);
        var handler = CreateHandler(time);
        var code = handler.GenerateCode(RfcSecret);

        time.Advance(TimeSpan.FromSeconds(120));

        Assert.False(handler.Verify(RfcSecret, code, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12345a")]
    [InlineData("000000")]
    public void Verify_WrongOrMalformedCode_Fails(string code)
    {
        Assert.False(CreateHandler().Verify(RfcSecret, code, out _));
    }

    [Fact]
    public void Verify_InvalidSecret_FailsWithoutThrowing()
    {
        Assert.False(CreateHandler().Verify("not base32 !", "123456", out _));
        Assert.False(CreateHandler().Verify("", "123456", out _));
        Assert.Throws<ArgumentException>(() => CreateHandler().GenerateCode("not base32 !"));
    }

    [Fact]
    public void Verify_ZeroDrift_AcceptsOnlyCurrentStep()
    {
        var handler = CreateHandler(configure: o => o.AllowedDriftSteps = 0);

        Assert.True(handler.Verify(RfcSecret, handler.GenerateCode(RfcSecret), out _));
        Assert.False(handler.Verify(RfcSecret, handler.GenerateCode(RfcSecret, Start.AddSeconds(-30)), out _));
    }

    [Fact]
    public void ProvisioningUri_ContainsEscapedLabelAndParameters()
    {
        var uri = CreateHandler().BuildProvisioningUri(RfcSecret.ToLowerInvariant(), "ann@example.com", "My App");

        Assert.Equal("otpauth", uri.Scheme);
        Assert.StartsWith("otpauth://totp/My%20App:ann%40example.com?", uri.AbsoluteUri, StringComparison.Ordinal);
        Assert.Contains($"secret={RfcSecret}", uri.AbsoluteUri, StringComparison.Ordinal);
        Assert.Contains("issuer=My%20App", uri.AbsoluteUri, StringComparison.Ordinal);
        Assert.Contains("digits=6", uri.AbsoluteUri, StringComparison.Ordinal);
        Assert.Contains("period=30", uri.AbsoluteUri, StringComparison.Ordinal);
    }

    [Fact]
    public void ProvisioningUri_InvalidArguments_Throw()
    {
        var handler = CreateHandler();

        Assert.Throws<ArgumentException>(() => handler.BuildProvisioningUri(RfcSecret, "", "Issuer"));
        Assert.Throws<ArgumentException>(() => handler.BuildProvisioningUri(RfcSecret, "acct", " "));
        Assert.Throws<ArgumentException>(() => handler.BuildProvisioningUri("!!", "acct", "Issuer"));
    }

    [Fact]
    public void InvalidOptions_Throw()
    {
        var time = new FakeTimeProvider(Start);

        Assert.Throws<ArgumentOutOfRangeException>(() => new TotpHandler(new TotpOptions { Digits = 7 }, time));
        Assert.Throws<ArgumentOutOfRangeException>(() => new TotpHandler(new TotpOptions { PeriodSeconds = 1 }, time));
        Assert.Throws<ArgumentOutOfRangeException>(() => new TotpHandler(new TotpOptions { AllowedDriftSteps = 9 }, time));
    }

    [Fact]
    public void AddTotp_ResolvesHandlerAndValidatesAtStartup()
    {
        using var provider = new ServiceCollection().AddTotp(o => o.Digits = 8).BuildServiceProvider();

        provider.GetRequiredService<IStartupValidator>().Validate();
        Assert.Equal(8, provider.GetRequiredService<ITotpHandler>().GenerateCode(RfcSecret).Length);

        using var broken = new ServiceCollection().AddTotp(o => o.Digits = 5).BuildServiceProvider();
        Assert.Throws<OptionsValidationException>(() => broken.GetRequiredService<IStartupValidator>().Validate());
    }
}
