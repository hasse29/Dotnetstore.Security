using System.Net;
using Dotnetstore.Security.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Dotnetstore.Security.AspNetCore.Tests;

public class SecurityHeadersAndRateLimitTests
{
    private static async Task<WebApplication> StartAsync(
        Action<IServiceCollection>? configureServices = null,
        Action<WebApplication>? configureApp = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        configureServices?.Invoke(builder.Services);

        var app = builder.Build();
        app.UseSecurityHeaders();
        configureApp?.Invoke(app);
        app.MapGet("/", () => "ok");
        app.MapGet("/custom", (HttpContext context) =>
        {
            context.Response.Headers["X-Frame-Options"] = "SAMEORIGIN";
            return "custom";
        });

        await app.StartAsync();
        return app;
    }

    private static HttpClient Client(WebApplication app, string baseAddress = "http://localhost/")
    {
        var client = app.GetTestClient();
        client.BaseAddress = new Uri(baseAddress);
        return client;
    }

    [Fact]
    public async Task Defaults_AreAddedToResponses()
    {
        await using var app = await StartAsync();

        using var response = await Client(app).GetAsync("/", TestContext.Current.CancellationToken);

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("default-src 'none'", response.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
        Assert.Contains("camera=()", response.Headers.GetValues("Permissions-Policy").Single(), StringComparison.Ordinal);
        Assert.Equal("same-origin", response.Headers.GetValues("Cross-Origin-Opener-Policy").Single());
        Assert.Equal("same-origin", response.Headers.GetValues("Cross-Origin-Resource-Policy").Single());
        Assert.False(response.Headers.Contains("Cache-Control"));
    }

    [Fact]
    public async Task StrictTransportSecurity_IsSentOnlyOverHttps()
    {
        await using var app = await StartAsync();

        using var http = await Client(app).GetAsync("/", TestContext.Current.CancellationToken);
        using var https = await Client(app, "https://localhost/").GetAsync("/", TestContext.Current.CancellationToken);

        Assert.False(http.Headers.Contains("Strict-Transport-Security"));
        Assert.Equal("max-age=31536000; includeSubDomains", https.Headers.GetValues("Strict-Transport-Security").Single());
    }

    [Fact]
    public async Task HeadersSetByTheApplication_AreNotOverwritten()
    {
        await using var app = await StartAsync();

        using var response = await Client(app).GetAsync("/custom", TestContext.Current.CancellationToken);

        Assert.Equal("SAMEORIGIN", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
    }

    [Fact]
    public async Task Options_CanChangeAndOmitHeaders()
    {
        await using var app = await StartAsync(services => services.AddSecurityHeaders(o =>
        {
            o.ContentSecurityPolicy = "default-src 'self'";
            o.FrameOptions = null;
            o.CacheControl = "no-store";
        }));

        using var response = await Client(app).GetAsync("/", TestContext.Current.CancellationToken);

        Assert.Equal("default-src 'self'", response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.False(response.Headers.Contains("X-Frame-Options"));
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task HeadersAreAlsoAddedToErrorResponses()
    {
        await using var app = await StartAsync();

        using var response = await Client(app).GetAsync("/does-not-exist", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
    }

    [Fact]
    public async Task LoginRateLimit_Returns429AfterThePermitLimit()
    {
        await using var app = await StartAsync(
            services => services.AddLoginRateLimiting(o => o.PermitLimit = 2),
            web =>
            {
                web.UseRateLimiter();
                web.MapPost("/login", () => "ok").RequireRateLimiting(RateLimitingExtensions.LoginPolicy);
            });
        var client = Client(app);

        using var first = await client.PostAsync("/login", null, TestContext.Current.CancellationToken);
        using var second = await client.PostAsync("/login", null, TestContext.Current.CancellationToken);
        using var third = await client.PostAsync("/login", null, TestContext.Current.CancellationToken);
        using var unlimited = await client.GetAsync("/", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, third.StatusCode);
        Assert.Equal(HttpStatusCode.OK, unlimited.StatusCode);
    }

    [Fact]
    public void LoginRateLimit_InvalidOptions_Throw()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentOutOfRangeException>(() => services.AddLoginRateLimiting(o => o.PermitLimit = 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => services.AddLoginRateLimiting(o => o.Window = TimeSpan.Zero));
    }
}
