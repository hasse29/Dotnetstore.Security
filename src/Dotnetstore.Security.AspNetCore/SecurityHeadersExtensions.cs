using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace Dotnetstore.Security.AspNetCore;

/// <summary>
/// Registration of the security headers middleware.
/// </summary>
public static class SecurityHeadersExtensions
{
    /// <summary>
    /// Configures the headers added by <see cref="UseSecurityHeaders"/>. Optional: the defaults apply without it.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Callback to change <see cref="SecurityHeadersOptions"/>.</param>
    /// <returns>The same <paramref name="services"/> instance for chaining.</returns>
    public static IServiceCollection AddSecurityHeaders(
        this IServiceCollection services,
        Action<SecurityHeadersOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.AddOptions<SecurityHeadersOptions>().Configure(configure);
        return services;
    }

    /// <summary>
    /// Adds security headers (<c>X-Content-Type-Options</c>, <c>X-Frame-Options</c>, <c>Content-Security-Policy</c>,
    /// <c>Referrer-Policy</c>, <c>Permissions-Policy</c>, cross-origin policies and, on HTTPS,
    /// <c>Strict-Transport-Security</c>) to every response. Place it early in the pipeline so error and
    /// short-circuited responses get the headers too.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The same <paramref name="app"/> for chaining.</returns>
    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        return app.UseMiddleware<SecurityHeadersMiddleware>();
    }
}
