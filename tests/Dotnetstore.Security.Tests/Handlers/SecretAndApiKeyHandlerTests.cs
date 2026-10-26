using System.Security.Cryptography;
using Dotnetstore.Security.Extensions;
using Dotnetstore.Security.Handlers;
using Microsoft.Extensions.DependencyInjection;

namespace Dotnetstore.Security.Tests.Handlers;

public class SecretAndApiKeyHandlerTests
{
    private readonly SecretHandler _secrets = new();
    private readonly ApiKeyHandler _apiKeys = new();

    [Fact]
    public void Generate_ReturnsUrlSafeRandomSecretWithMatchingHash()
    {
        var first = _secrets.Generate();
        var second = _secrets.Generate();

        Assert.Equal(43, first.Value.Length);
        Assert.DoesNotContain('+', first.Value);
        Assert.DoesNotContain('/', first.Value);
        Assert.NotEqual(first.Value, second.Value);
        Assert.NotEqual(first.Value, first.Hash);
        Assert.Equal(first.Hash, _secrets.Hash(first.Value));
        Assert.True(_secrets.Verify(first.Value, first.Hash));
        Assert.False(_secrets.Verify(second.Value, first.Hash));
    }

    [Theory]
    [InlineData(15)]
    [InlineData(129)]
    public void Generate_OutOfRangeSize_Throws(int size)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _secrets.Generate(size));
    }

    [Theory]
    [InlineData("", "hash")]
    [InlineData("secret", "")]
    public void Verify_EmptyInput_ReturnsFalse(string secret, string hash)
    {
        Assert.False(_secrets.Verify(secret, hash));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(9)]
    public void GenerateCode_HasRequestedDigitsOnly(int digits)
    {
        for (var i = 0; i < 200; i++)
        {
            var code = _secrets.GenerateCode(digits);

            Assert.Equal(digits, code.Length);
            Assert.All(code, c => Assert.True(char.IsAsciiDigit(c)));
        }
    }

    [Fact]
    public void GenerateCode_CoversLeadingZerosAndVaries()
    {
        var codes = Enumerable.Range(0, 2000).Select(_ => _secrets.GenerateCode(4)).ToHashSet();

        Assert.True(codes.Count > 1000);
        Assert.Contains(codes, c => c.StartsWith('0'));
    }

    [Theory]
    [InlineData(3)]
    [InlineData(10)]
    public void GenerateCode_OutOfRangeDigits_Throws(int digits)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _secrets.GenerateCode(digits));
    }

    [Fact]
    public void RecoveryCodes_AreFormattedUniqueAndVerifiable()
    {
        var codes = _secrets.GenerateRecoveryCodes(10);

        Assert.Equal(10, codes.Count);
        Assert.Equal(10, codes.Select(c => c.Code).Distinct().Count());
        Assert.All(codes, c =>
        {
            Assert.Matches("^[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}$", c.Code);
            Assert.True(_secrets.VerifyRecoveryCode(c.Code, c.Hash));
            Assert.Equal(c.Hash, _secrets.HashRecoveryCode(c.Code));
        });
    }

    [Fact]
    public void RecoveryCodes_IgnoreCaseSpacesAndDashes()
    {
        var code = _secrets.GenerateRecoveryCodes(1)[0];
        var sloppy = code.Code.ToLowerInvariant().Replace("-", " ", StringComparison.Ordinal);

        Assert.True(_secrets.VerifyRecoveryCode(sloppy, code.Hash));
        Assert.True(_secrets.VerifyRecoveryCode(code.Code.Replace("-", "", StringComparison.Ordinal), code.Hash));
        Assert.False(_secrets.VerifyRecoveryCode("AAAAA-AAAAA", code.Hash));
        Assert.False(_secrets.VerifyRecoveryCode("", code.Hash));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(51)]
    public void RecoveryCodes_OutOfRangeCount_Throws(int count)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _secrets.GenerateRecoveryCodes(count));
    }

    [Fact]
    public void ApiKey_CreateProducesPrefixIdSecretAndHash()
    {
        var key = _apiKeys.Create("live");
        var parts = key.Value.Split('.');

        Assert.Equal(3, parts.Length);
        Assert.Equal("live", parts[0]);
        Assert.Equal(key.Prefix, parts[0]);
        Assert.Equal(key.Id, parts[1]);
        Assert.DoesNotContain(parts[2], key.Hash);
        Assert.NotEqual(key.Value, _apiKeys.Create("live").Value);
    }

    [Fact]
    public void ApiKey_ParseThenVerify_RoundTrips()
    {
        var key = _apiKeys.Create("test1");

        Assert.True(_apiKeys.TryParse(key.Value, out var prefix, out var id));
        Assert.Equal("test1", prefix);
        Assert.Equal(key.Id, id);
        Assert.True(_apiKeys.Verify(key.Value, key.Hash));
    }

    [Fact]
    public void ApiKey_WrongSecretOrMalformed_IsRejected()
    {
        var key = _apiKeys.Create("live");
        var other = _apiKeys.Create("live");
        var forged = $"{key.Prefix}.{key.Id}.{other.Value.Split('.')[2]}";

        Assert.False(_apiKeys.Verify(forged, key.Hash));
        Assert.False(_apiKeys.Verify(key.Value, other.Hash));
        Assert.False(_apiKeys.Verify("garbage", key.Hash));
        Assert.False(_apiKeys.TryParse("a.b", out _, out _));
        Assert.False(_apiKeys.TryParse("Live.id.secret", out _, out _));
        Assert.False(_apiKeys.TryParse("live..secret", out _, out _));
        Assert.False(_apiKeys.TryParse("", out _, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("Live")]
    [InlineData("has space")]
    [InlineData("has.dot")]
    [InlineData("waytoolongprefixvalue")]
    public void ApiKey_InvalidPrefix_Throws(string prefix)
    {
        Assert.Throws<ArgumentException>(() => _apiKeys.Create(prefix));
    }

    [Fact]
    public void AddSecrets_RegistersBothHandlers()
    {
        using var provider = new ServiceCollection().AddSecrets().BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<ISecretHandler>());
        Assert.NotNull(provider.GetRequiredService<IApiKeyHandler>());
        Assert.NotEmpty(RandomNumberGenerator.GetBytes(1));
    }
}
