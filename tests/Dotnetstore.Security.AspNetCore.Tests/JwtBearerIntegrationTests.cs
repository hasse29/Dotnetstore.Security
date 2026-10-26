using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using Dotnetstore.Security.AspNetCore;
using Dotnetstore.Security.Extensions;
using Dotnetstore.Security.Handlers;
using Dotnetstore.Security.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace Dotnetstore.Security.AspNetCore.Tests;

public class JwtBearerIntegrationTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    private static async Task<WebApplication> StartAsync(FakeTimeProvider time, Action<TokenOptions> configure)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton<TimeProvider>(time);
        builder.Services.AddTokens(configure);
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddSecurityJwtBearer();
        builder.Services.AddAuthorization();

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/me", (ClaimsPrincipal user) => user.FindFirst("sub")?.Value).RequireAuthorization();
        app.MapGet("/admin", () => "ok").RequireAuthorization(policy => policy.RequireRole("admin"));

        await app.StartAsync();
        return app;
    }

    private static void ConfigureHs256(TokenOptions options, string key)
    {
        options.Issuer = "https://issuer.test";
        options.Audience = "api.test";
        options.ClockSkew = TimeSpan.Zero;
        options.SigningKeys["k1"] = key;
        options.CurrentSigningKeyId = "k1";
    }

    private static string NewKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    private static async Task<HttpResponseMessage> GetAsync(WebApplication app, string path, string? token = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return await app.GetTestClient().SendAsync(request, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task NoToken_Returns401()
    {
        await using var app = await StartAsync(new FakeTimeProvider(Start), o => ConfigureHs256(o, NewKey()));

        using var response = await GetAsync(app, "/me");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ValidToken_Returns200AndSubIsNotRemapped()
    {
        await using var app = await StartAsync(new FakeTimeProvider(Start), o => ConfigureHs256(o, NewKey()));
        var token = app.Services.GetRequiredService<ITokenHandler>().CreateAccessToken("user-42");

        using var response = await GetAsync(app, "/me", token.Value);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("user-42", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ExpiredToken_Returns401()
    {
        var time = new FakeTimeProvider(Start);
        await using var app = await StartAsync(time, o => ConfigureHs256(o, NewKey()));
        var token = app.Services.GetRequiredService<ITokenHandler>().CreateAccessToken("user-42");

        time.Advance(TimeSpan.FromMinutes(16));
        using var response = await GetAsync(app, "/me", token.Value);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TamperedToken_Returns401()
    {
        await using var app = await StartAsync(new FakeTimeProvider(Start), o => ConfigureHs256(o, NewKey()));
        var handler = app.Services.GetRequiredService<ITokenHandler>();
        var parts = handler.CreateAccessToken("user").Value.Split('.');
        var other = handler.CreateAccessToken("admin").Value.Split('.');

        using var response = await GetAsync(app, "/me", $"{parts[0]}.{other[1]}.{parts[2]}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TokenFromAnotherIssuerKey_Returns401()
    {
        await using var app = await StartAsync(new FakeTimeProvider(Start), o => ConfigureHs256(o, NewKey()));
        await using var other = await StartAsync(new FakeTimeProvider(Start), o => ConfigureHs256(o, NewKey()));
        var foreign = other.Services.GetRequiredService<ITokenHandler>().CreateAccessToken("user");

        using var response = await GetAsync(app, "/me", foreign.Value);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task RoleClaims_DriveAuthorization()
    {
        await using var app = await StartAsync(new FakeTimeProvider(Start), o => ConfigureHs256(o, NewKey()));
        var handler = app.Services.GetRequiredService<ITokenHandler>();
        var admin = handler.CreateAccessToken("a", [new Claim("role", "admin")]);
        var user = handler.CreateAccessToken("b", [new Claim("role", "user")]);

        using var adminResponse = await GetAsync(app, "/admin", admin.Value);
        using var userResponse = await GetAsync(app, "/admin", user.Value);

        Assert.Equal(HttpStatusCode.OK, adminResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, userResponse.StatusCode);
    }

    [Fact]
    public async Task ValidateOnlyService_AcceptsTokensSignedByIssuerPrivateKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privatePem = ecdsa.ExportPkcs8PrivateKeyPem();
        var publicPem = ecdsa.ExportSubjectPublicKeyInfoPem();
        var time = new FakeTimeProvider(Start);

        await using var issuer = await StartAsync(time, o =>
        {
            o.Algorithm = SigningAlgorithm.ES256;
            o.Issuer = "https://issuer.test";
            o.Audience = "api.test";
            o.ClockSkew = TimeSpan.Zero;
            o.SigningKeys["k1"] = privatePem;
            o.CurrentSigningKeyId = "k1";
        });
        await using var api = await StartAsync(time, o =>
        {
            o.Algorithm = SigningAlgorithm.ES256;
            o.Issuer = "https://issuer.test";
            o.Audience = "api.test";
            o.ClockSkew = TimeSpan.Zero;
            o.SigningKeys["k1"] = publicPem;
        });
        var token = issuer.Services.GetRequiredService<ITokenHandler>().CreateAccessToken("user-7");

        using var response = await GetAsync(api, "/me", token.Value);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("user-7", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public void AddSecurityJwtBearer_NullBuilder_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => AuthenticationBuilderExtensions.AddSecurityJwtBearer(null!));
    }
}
