using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;

namespace Dotnetstore.Security.AspNetCore;

/// <summary>
/// Configuration for the login rate limiting policy.
/// </summary>
public sealed class LoginRateLimitOptions
{
    /// <summary>The number of requests allowed per client within <see cref="Window"/>. Defaults to 10.</summary>
    public int PermitLimit { get; set; } = 10;

    /// <summary>The length of the counting window. Defaults to one minute.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
}

/// <summary>
/// A rate limiting policy for credential endpoints such as login, token refresh and password reset.
/// </summary>
public static class RateLimitingExtensions
{
    /// <summary>The name of the policy added by <see cref="AddLoginRateLimiting"/>.</summary>
    public const string LoginPolicy = "dotnetstore-login";

    /// <summary>
    /// Adds a per-client-IP fixed-window rate limit named <see cref="LoginPolicy"/>, answering 429 when exceeded.
    /// Apply it with <c>.RequireRateLimiting(RateLimitingExtensions.LoginPolicy)</c> and call
    /// <c>app.UseRateLimiter()</c>. Behind a reverse proxy, configure forwarded headers so the client IP is the
    /// real one. This limits request volume only; use <c>ILockoutHandler</c> to lock individual accounts.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Optional callback to configure <see cref="LoginRateLimitOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddLoginRateLimiting(
        this IServiceCollection services,
        Action<LoginRateLimitOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        var options = new LoginRateLimitOptions();
        configure?.Invoke(options);

        if (options.PermitLimit < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(configure), options.PermitLimit, "PermitLimit must be at least 1.");
        }

        if (options.Window <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(configure), options.Window, "Window must be positive.");
        }

        services.AddRateLimiter(limiter =>
        {
            limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            limiter.AddPolicy(LoginPolicy, context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = options.PermitLimit,
                        Window = options.Window,
                        QueueLimit = 0,
                    }));
        });

        return services;
    }
}
