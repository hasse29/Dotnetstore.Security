using System.Security.Claims;
using System.Security.Cryptography;
using Dotnetstore.Security.Extensions;
using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Dotnetstore.Security.Tests.Handlers;

public class TokenHandlerTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static string NewKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    private static TokenOptions Options(string currentId = "k1", params (string Id, string Value)[] keys)
    {
        var options = new TokenOptions
        {
            Issuer = "https://issuer.test",
            Audience = "api.test",
            CurrentSigningKeyId = currentId,
            ClockSkew = TimeSpan.Zero,
        };
        foreach (var (id, value) in keys.Length > 0 ? keys : [("k1", NewKey())])
        {
            options.SigningKeys[id] = value;
        }

        return options;
    }

    private static TokenHandler CreateHandler(TokenOptions? options = null, FakeTimeProvider? time = null) =>
        new(options ?? Options(), time ?? new FakeTimeProvider(Start));

    [Fact]
    public async Task AccessToken_RoundTripsSubjectAndClaims()
    {
        var handler = CreateHandler();

        var token = handler.CreateAccessToken(
            "user-1",
            [new Claim("role", "admin"), new Claim("role", "editor"), new Claim("email", "a@b.test")]);
        var principal = await handler.ValidateAccessTokenAsync(token.Value);

        Assert.NotNull(principal);
        Assert.Equal("user-1", principal.FindFirst("sub")?.Value);
        Assert.Equal("a@b.test", principal.FindFirst("email")?.Value);
        Assert.True(principal.IsInRole("admin"));
        Assert.True(principal.IsInRole("editor"));
        Assert.False(principal.IsInRole("other"));
    }

    [Fact]
    public void AccessToken_HasExpectedHeaderAndClaims()
    {
        var token = CreateHandler().CreateAccessToken("user-1");
        var jwt = new JsonWebToken(token.Value);

        Assert.Equal("HS256", jwt.Alg);
        Assert.Equal("k1", jwt.Kid);
        Assert.Equal("https://issuer.test", jwt.Issuer);
        Assert.Contains("api.test", jwt.Audiences);
        Assert.Equal(Start.AddMinutes(15), token.ExpiresAt);
        Assert.Equal(Start.AddMinutes(15).ToUnixTimeSeconds(), new DateTimeOffset(jwt.ValidTo).ToUnixTimeSeconds());
        Assert.False(string.IsNullOrEmpty(jwt.Id));
    }

    [Fact]
    public void AccessToken_EachTokenHasUniqueId()
    {
        var handler = CreateHandler();

        Assert.NotEqual(
            new JsonWebToken(handler.CreateAccessToken("u").Value).Id,
            new JsonWebToken(handler.CreateAccessToken("u").Value).Id);
    }

    [Fact]
    public async Task AccessToken_Expires()
    {
        var time = new FakeTimeProvider(Start);
        var handler = CreateHandler(time: time);
        var token = handler.CreateAccessToken("user-1");

        time.Advance(TimeSpan.FromMinutes(14));
        Assert.NotNull(await handler.ValidateAccessTokenAsync(token.Value));

        time.Advance(TimeSpan.FromMinutes(2));
        Assert.Null(await handler.ValidateAccessTokenAsync(token.Value));
    }

    [Fact]
    public async Task AccessToken_TamperedPayload_IsRejected()
    {
        var handler = CreateHandler();
        var parts = handler.CreateAccessToken("user-1").Value.Split('.');
        var other = handler.CreateAccessToken("admin").Value.Split('.');

        Assert.Null(await handler.ValidateAccessTokenAsync($"{parts[0]}.{other[1]}.{parts[2]}"));
    }

    [Fact]
    public async Task AccessToken_SignedWithOtherKey_IsRejected()
    {
        var token = CreateHandler(Options()).CreateAccessToken("user-1");

        Assert.Null(await CreateHandler(Options()).ValidateAccessTokenAsync(token.Value));
    }

    [Fact]
    public async Task AccessToken_WrongIssuerOrAudience_IsRejected()
    {
        var key = NewKey();
        var token = CreateHandler(Options("k1", ("k1", key))).CreateAccessToken("user-1");

        var wrongIssuer = Options("k1", ("k1", key));
        wrongIssuer.Issuer = "https://evil.test";
        var wrongAudience = Options("k1", ("k1", key));
        wrongAudience.Audience = "other-api";

        Assert.Null(await CreateHandler(wrongIssuer).ValidateAccessTokenAsync(token.Value));
        Assert.Null(await CreateHandler(wrongAudience).ValidateAccessTokenAsync(token.Value));
    }

    [Fact]
    public async Task AccessToken_UnsignedAlgNone_IsRejected()
    {
        var handler = CreateHandler();
        var header = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode("""{"alg":"none","typ":"JWT"}""");
        var payload = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(
            """{"sub":"admin","iss":"https://issuer.test","aud":"api.test","exp":4102444800}""");

        Assert.Null(await handler.ValidateAccessTokenAsync($"{header}.{payload}."));
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("a.b.c")]
    public async Task AccessToken_Malformed_ReturnsNull(string token)
    {
        Assert.Null(await CreateHandler().ValidateAccessTokenAsync(token));
    }

    [Fact]
    public async Task KeyRotation_OldTokensStillValidate_NewTokensUseNewKey()
    {
        var oldKey = NewKey();
        var oldToken = CreateHandler(Options("k1", ("k1", oldKey))).CreateAccessToken("user-1");

        var rotated = CreateHandler(Options("k2", ("k1", oldKey), ("k2", NewKey())));
        var newToken = rotated.CreateAccessToken("user-1");

        Assert.NotNull(await rotated.ValidateAccessTokenAsync(oldToken.Value));
        Assert.Equal("k2", new JsonWebToken(newToken.Value).Kid);
        Assert.NotNull(await rotated.ValidateAccessTokenAsync(newToken.Value));
    }

    [Fact]
    public async Task KeyRotation_RetiredKeyRemoved_OldTokensRejected()
    {
        var oldToken = CreateHandler(Options("k1", ("k1", NewKey()))).CreateAccessToken("user-1");
        var rotated = CreateHandler(Options("k2", ("k2", NewKey())));

        Assert.Null(await rotated.ValidateAccessTokenAsync(oldToken.Value));
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("iss")]
    [InlineData("aud")]
    [InlineData("exp")]
    [InlineData("nbf")]
    [InlineData("iat")]
    [InlineData("jti")]
    public void CreateAccessToken_ReservedClaim_Throws(string type)
    {
        Assert.Throws<ArgumentException>(() => CreateHandler().CreateAccessToken("user-1", [new Claim(type, "x")]));
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void CreateAccessToken_EmptySubject_Throws(string subject)
    {
        Assert.Throws<ArgumentException>(() => CreateHandler().CreateAccessToken(subject));
    }

    [Fact]
    public void RefreshToken_IsRandomOpaqueAndHashed()
    {
        var handler = CreateHandler();

        var first = handler.CreateRefreshToken();
        var second = handler.CreateRefreshToken();

        Assert.NotEqual(first.Value, second.Value);
        Assert.NotEqual(first.Hash, second.Hash);
        Assert.NotEqual(first.Value, first.Hash);
        Assert.Equal(43, first.Value.Length);
        Assert.Equal(Start.AddDays(7), first.ExpiresAt);
        Assert.Equal(first.Hash, handler.HashRefreshToken(first.Value));
    }

    [Fact]
    public void RefreshToken_Verify_AcceptsOnlyMatchingToken()
    {
        var handler = CreateHandler();
        var token = handler.CreateRefreshToken();
        var other = handler.CreateRefreshToken();

        Assert.True(handler.VerifyRefreshToken(token.Value, token.Hash));
        Assert.False(handler.VerifyRefreshToken(other.Value, token.Hash));
        Assert.False(handler.VerifyRefreshToken(token.Hash, token.Hash));
        Assert.False(handler.VerifyRefreshToken("", token.Hash));
        Assert.False(handler.VerifyRefreshToken(token.Value, ""));
    }

    [Fact]
    public void Lifetimes_AreConfigurable()
    {
        var options = Options();
        options.AccessTokenLifetime = TimeSpan.FromMinutes(5);
        options.RefreshTokenLifetime = TimeSpan.FromDays(30);
        var handler = CreateHandler(options);

        Assert.Equal(Start.AddMinutes(5), handler.CreateAccessToken("u").ExpiresAt);
        Assert.Equal(Start.AddDays(30), handler.CreateRefreshToken().ExpiresAt);
    }

    [Fact]
    public void InvalidConfiguration_Throws()
    {
        var good = NewKey();
        var shortKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));

        Assert.Throws<ArgumentException>(() => CreateHandler(Mutate(o => o.Issuer = "")));
        Assert.Throws<ArgumentException>(() => CreateHandler(Mutate(o => o.Audience = " ")));
        Assert.Throws<ArgumentException>(() => CreateHandler(Mutate(o => o.SigningKeys.Clear())));
        Assert.Throws<ArgumentException>(() => CreateHandler(Mutate(o => o.CurrentSigningKeyId = "missing")));
        Assert.Throws<ArgumentException>(() => CreateHandler(Options("k1", ("k1", shortKey))));
        Assert.Throws<ArgumentException>(() => CreateHandler(Options("k1", ("k1", "not base64!!"))));
        Assert.Throws<ArgumentException>(() => CreateHandler(Options("bad id", ("bad id", good))));
        Assert.Throws<ArgumentOutOfRangeException>(() => CreateHandler(Mutate(o => o.AccessTokenLifetime = TimeSpan.Zero)));
        Assert.Throws<ArgumentOutOfRangeException>(() => CreateHandler(Mutate(o => o.RefreshTokenLifetime = TimeSpan.Zero)));
        Assert.Throws<ArgumentOutOfRangeException>(() => CreateHandler(Mutate(o => o.ClockSkew = TimeSpan.FromSeconds(-1))));
    }

    [Fact]
    public async Task AddTokens_ResolvesConfiguredSingleton()
    {
        var key = NewKey();
        using var provider = new ServiceCollection()
            .AddTokens(o =>
            {
                o.Issuer = "https://issuer.test";
                o.Audience = "api.test";
                o.SigningKeys["k1"] = key;
                o.CurrentSigningKeyId = "k1";
            })
            .BuildServiceProvider();

        var handler = provider.GetRequiredService<ITokenHandler>();

        Assert.Same(handler, provider.GetRequiredService<ITokenHandler>());
        Assert.NotNull(await handler.ValidateAccessTokenAsync(handler.CreateAccessToken("user-1").Value));
    }

    [Fact]
    public void AddTokens_WithoutConfiguration_ThrowsOnResolve()
    {
        using var provider = new ServiceCollection().AddTokens().BuildServiceProvider();

        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<ITokenHandler>());
        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IStartupValidator>().Validate());
    }

    private static (string Private, string Public) NewKeyPair(SigningAlgorithm algorithm, int rsaBits = 2048)
    {
        if (algorithm == SigningAlgorithm.RS256)
        {
            using var rsa = RSA.Create(rsaBits);
            return (rsa.ExportPkcs8PrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
        }

        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (ecdsa.ExportPkcs8PrivateKeyPem(), ecdsa.ExportSubjectPublicKeyInfoPem());
    }

    private static TokenOptions AsymmetricOptions(
        SigningAlgorithm algorithm,
        string? currentId,
        params (string Id, string Pem)[] keys)
    {
        var options = new TokenOptions
        {
            Algorithm = algorithm,
            Issuer = "https://issuer.test",
            Audience = "api.test",
            CurrentSigningKeyId = currentId,
            ClockSkew = TimeSpan.Zero,
        };
        foreach (var (id, pem) in keys)
        {
            options.SigningKeys[id] = pem;
        }

        return options;
    }

    [Theory]
    [InlineData(SigningAlgorithm.RS256, "RS256")]
    [InlineData(SigningAlgorithm.ES256, "ES256")]
    public async Task Asymmetric_RoundTripsAndWritesAlgorithmAndKeyId(SigningAlgorithm algorithm, string alg)
    {
        var (priv, _) = NewKeyPair(algorithm);
        var handler = CreateHandler(AsymmetricOptions(algorithm, "k1", ("k1", priv)));

        var token = handler.CreateAccessToken("user-1", [new Claim("role", "admin")]);
        var jwt = new JsonWebToken(token.Value);
        var principal = await handler.ValidateAccessTokenAsync(token.Value);

        Assert.Equal(alg, jwt.Alg);
        Assert.Equal("k1", jwt.Kid);
        Assert.NotNull(principal);
        Assert.True(principal.IsInRole("admin"));
    }

    [Theory]
    [InlineData(SigningAlgorithm.RS256)]
    [InlineData(SigningAlgorithm.ES256)]
    public async Task Asymmetric_ValidateOnlyHandler_ValidatesButCannotCreate(SigningAlgorithm algorithm)
    {
        var (priv, pub) = NewKeyPair(algorithm);
        var token = CreateHandler(AsymmetricOptions(algorithm, "k1", ("k1", priv))).CreateAccessToken("user-1");

        var validator = CreateHandler(AsymmetricOptions(algorithm, null, ("k1", pub)));

        Assert.NotNull(await validator.ValidateAccessTokenAsync(token.Value));
        Assert.Throws<InvalidOperationException>(() => validator.CreateAccessToken("user-1"));
    }

    [Theory]
    [InlineData(SigningAlgorithm.RS256)]
    [InlineData(SigningAlgorithm.ES256)]
    public async Task Asymmetric_TokenFromDifferentKeyPair_IsRejected(SigningAlgorithm algorithm)
    {
        var token = CreateHandler(AsymmetricOptions(algorithm, "k1", ("k1", NewKeyPair(algorithm).Private)))
            .CreateAccessToken("user-1");
        var other = CreateHandler(AsymmetricOptions(algorithm, "k1", ("k1", NewKeyPair(algorithm).Private)));

        Assert.Null(await other.ValidateAccessTokenAsync(token.Value));
    }

    [Fact]
    public async Task Asymmetric_Rotation_OldPublicKeyStillValidatesOldTokens()
    {
        var (oldPriv, oldPub) = NewKeyPair(SigningAlgorithm.ES256);
        var oldToken = CreateHandler(AsymmetricOptions(SigningAlgorithm.ES256, "k1", ("k1", oldPriv))).CreateAccessToken("u");

        var rotated = CreateHandler(AsymmetricOptions(
            SigningAlgorithm.ES256,
            "k2",
            ("k1", oldPub),
            ("k2", NewKeyPair(SigningAlgorithm.ES256).Private)));
        var newToken = rotated.CreateAccessToken("u");

        Assert.NotNull(await rotated.ValidateAccessTokenAsync(oldToken.Value));
        Assert.Equal("k2", new JsonWebToken(newToken.Value).Kid);
        Assert.NotNull(await rotated.ValidateAccessTokenAsync(newToken.Value));
    }

    [Fact]
    public async Task Algorithm_Mismatch_IsRejected()
    {
        var hsToken = CreateHandler().CreateAccessToken("user-1");
        var (priv, _) = NewKeyPair(SigningAlgorithm.RS256);
        var rsHandler = CreateHandler(AsymmetricOptions(SigningAlgorithm.RS256, "k1", ("k1", priv)));
        var rsToken = rsHandler.CreateAccessToken("user-1");

        Assert.Null(await rsHandler.ValidateAccessTokenAsync(hsToken.Value));
        Assert.Null(await CreateHandler().ValidateAccessTokenAsync(rsToken.Value));
    }

    [Fact]
    public async Task Algorithm_HmacTokenSignedWithPublicKeyAsSecret_IsRejected()
    {
        var (priv, pub) = NewKeyPair(SigningAlgorithm.RS256);
        var rsHandler = CreateHandler(AsymmetricOptions(SigningAlgorithm.RS256, "k1", ("k1", priv)));

        var forged = new JsonWebTokenHandler().CreateToken(new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
        {
            Issuer = "https://issuer.test",
            Audience = "api.test",
            Expires = Start.AddMinutes(5).UtcDateTime,
            Claims = new Dictionary<string, object> { ["sub"] = "admin" },
            SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(pub + pub))
                {
                    KeyId = "k1",
                },
                Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256),
        });

        Assert.Null(await rsHandler.ValidateAccessTokenAsync(forged));
    }

    [Fact]
    public void Asymmetric_InvalidConfiguration_Throws()
    {
        var (rsPriv, rsPub) = NewKeyPair(SigningAlgorithm.RS256);
        var (ecPriv, _) = NewKeyPair(SigningAlgorithm.ES256);
        var weakRsa = NewKeyPair(SigningAlgorithm.RS256, 1024).Private;
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        // private key but no current id
        Assert.Throws<ArgumentException>(() => CreateHandler(AsymmetricOptions(SigningAlgorithm.RS256, null, ("k1", rsPriv))));
        // current id names a public key
        Assert.Throws<ArgumentException>(() => CreateHandler(AsymmetricOptions(SigningAlgorithm.RS256, "k1", ("k1", rsPub))));
        // not PEM
        Assert.Throws<ArgumentException>(() => CreateHandler(AsymmetricOptions(SigningAlgorithm.RS256, "k1", ("k1", "nope"))));
        // wrong key type for the algorithm
        Assert.Throws<ArgumentException>(() => CreateHandler(AsymmetricOptions(SigningAlgorithm.RS256, "k1", ("k1", ecPriv))));
        Assert.Throws<ArgumentException>(() => CreateHandler(AsymmetricOptions(SigningAlgorithm.ES256, "k1", ("k1", rsPriv))));
        // RSA too small, wrong curve
        Assert.Throws<ArgumentException>(() => CreateHandler(AsymmetricOptions(SigningAlgorithm.RS256, "k1", ("k1", weakRsa))));
        Assert.Throws<ArgumentException>(() => CreateHandler(
            AsymmetricOptions(SigningAlgorithm.ES256, "k1", ("k1", p384.ExportPkcs8PrivateKeyPem()))));
        // HS256 needs a current id
        Assert.Throws<ArgumentException>(() => CreateHandler(Mutate(o => o.CurrentSigningKeyId = null)));
    }

    private static TokenOptions Mutate(Action<TokenOptions> change)
    {
        var options = Options();
        change(options);
        return options;
    }
}
