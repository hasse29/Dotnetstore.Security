using System.Security.Cryptography;
using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Models;
using Dotnetstore.Security.Tool;

namespace Dotnetstore.Security.Tests.Tooling;

public class KeyGeneratorAndCliTests
{
    [Fact]
    public void CreateSecret_ProducesRequestedLengthAndIsRandom()
    {
        var secret = KeyGenerator.CreateSecret(48);

        Assert.Equal(48, Convert.FromBase64String(secret).Length);
        Assert.NotEqual(secret, KeyGenerator.CreateSecret(48));
        Assert.Throws<ArgumentOutOfRangeException>(() => KeyGenerator.CreateSecret(16));
    }

    [Fact]
    public void GeneratedKeys_AreAcceptedByTheMatchingOptions()
    {
        var encryption = new EncryptionOptions { CurrentKeyId = "k1" };
        encryption.Keys["k1"] = KeyGenerator.CreateEncryptionKey();
        _ = new EncryptionHandler(encryption);

        var argon2 = new Argon2Options { MemorySizeKiB = 64, Iterations = 1, DegreeOfParallelism = 2, CurrentPepperId = "p1" };
        argon2.Peppers["p1"] = KeyGenerator.CreatePepper();
        _ = new HashHandler(argon2);

        var hs = new TokenOptions { Issuer = "i", Audience = "a", CurrentSigningKeyId = "k1" };
        hs.SigningKeys["k1"] = KeyGenerator.CreateSecret();
        using var hsHandler = new TokenHandler(hs, TimeProvider.System);
        Assert.NotNull(hsHandler.CreateAccessToken("u"));
    }

    [Theory]
    [InlineData(SigningAlgorithm.RS256)]
    [InlineData(SigningAlgorithm.ES256)]
    public async Task GeneratedKeyPairs_SignAndValidate(SigningAlgorithm algorithm)
    {
        var (priv, pub) = algorithm == SigningAlgorithm.RS256
            ? KeyGenerator.CreateRsaKeyPair(2048)
            : KeyGenerator.CreateEcKeyPair();

        var signing = new TokenOptions { Algorithm = algorithm, Issuer = "i", Audience = "a", CurrentSigningKeyId = "k1" };
        signing.SigningKeys["k1"] = priv;
        var validating = new TokenOptions { Algorithm = algorithm, Issuer = "i", Audience = "a" };
        validating.SigningKeys["k1"] = pub;

        using var issuer = new TokenHandler(signing, TimeProvider.System);
        using var validator = new TokenHandler(validating, TimeProvider.System);

        Assert.NotNull(await validator.ValidateAccessTokenAsync(issuer.CreateAccessToken("u").Value));
    }

    [Fact]
    public void CreateRsaKeyPair_RejectsWeakKeys()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => KeyGenerator.CreateRsaKeyPair(1024));
    }

    [Fact]
    public void Calibrate_ReturnsValidOptionsAndStopsOnceTargetIsReached()
    {
        var (options, elapsed) = Argon2Calibrator.Calibrate(TimeSpan.FromMilliseconds(1), memorySizeKiB: 64, degreeOfParallelism: 2);

        Assert.Equal(64, options.MemorySizeKiB);
        Assert.InRange(options.Iterations, 1, 64);
        Assert.True(elapsed > TimeSpan.Zero);
        _ = new HashHandler(options);
    }

    [Fact]
    public void Calibrate_NonPositiveTarget_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Argon2Calibrator.Calibrate(TimeSpan.Zero));
    }

    private static (int Code, string Out, string Err) RunCli(params string[] args)
    {
        using var output = new StringWriter();
        using var error = new StringWriter();
        var code = Cli.Run(args, output, error);
        return (code, output.ToString(), error.ToString());
    }

    [Fact]
    public void Cli_Secret_PrintsBase64WithRequestedSize()
    {
        var (code, output, _) = RunCli("secret", "--bytes", "40");

        Assert.Equal(0, code);
        Assert.Equal(40, Convert.FromBase64String(output.Trim()).Length);
    }

    [Theory]
    [InlineData("encryption-key", 32)]
    [InlineData("pepper", 32)]
    public void Cli_FixedSizeSecrets(string command, int size)
    {
        var (code, output, _) = RunCli(command);

        Assert.Equal(0, code);
        Assert.Equal(size, Convert.FromBase64String(output.Trim()).Length);
    }

    [Theory]
    [InlineData("ec")]
    [InlineData("rsa")]
    public void Cli_KeyPairs_PrintPrivateAndPublicPem(string command)
    {
        var (code, output, _) = RunCli(command == "rsa" ? ["rsa", "--bits", "2048"] : [command]);

        Assert.Equal(0, code);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", output);
        Assert.Contains("-----BEGIN PUBLIC KEY-----", output);
    }

    [Fact]
    public void Cli_Calibrate_PrintsSettings()
    {
        var (code, output, _) = RunCli("calibrate", "--target-ms", "1", "--memory-kib", "64", "--parallelism", "2");

        Assert.Equal(0, code);
        Assert.Contains("MemorySizeKiB: 64", output);
        Assert.Contains("Iterations:", output);
    }

    [Theory]
    [InlineData(new string[0], 0)]
    [InlineData(new[] { "help" }, 0)]
    [InlineData(new[] { "bogus" }, 1)]
    [InlineData(new[] { "secret", "--bytes", "abc" }, 2)]
    [InlineData(new[] { "secret", "--bytes", "8" }, 2)]
    [InlineData(new[] { "secret", "--bytes" }, 2)]
    [InlineData(new[] { "secret", "stray" }, 2)]
    [InlineData(new[] { "secret", "--bytes", "99999999999" }, 2)]
    public void Cli_ExitCodes(string[] args, int expected)
    {
        Assert.Equal(expected, RunCli(args).Code);
    }

    [Fact]
    public void Cli_Secret_WritesNothingToErrorStream()
    {
        var (_, _, error) = RunCli("secret");

        Assert.Empty(error);
    }
}
