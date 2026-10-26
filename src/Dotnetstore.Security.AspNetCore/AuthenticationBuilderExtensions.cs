using Dotnetstore.Security.Handlers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;

namespace Dotnetstore.Security.AspNetCore;

/// <summary>
/// ASP.NET Core authentication registration for Dotnetstore.Security access tokens.
/// </summary>
public static class AuthenticationBuilderExtensions
{
    /// <summary>
    /// Adds JWT bearer authentication that validates access tokens exactly as <see cref="ITokenHandler"/> does:
    /// the same issuer, audience, signing keys, pinned algorithm, and lifetime rules.
    /// </summary>
    /// <remarks>
    /// Call <c>AddTokens</c> first to configure the token options. Claim names are not remapped, so the
    /// <c>sub</c> and <c>role</c> claims keep their JWT names and <c>[Authorize(Roles = "...")]</c> works with
    /// <c>role</c> claims.
    /// </remarks>
    /// <param name="builder">The authentication builder, typically from <c>AddAuthentication()</c>.</param>
    /// <param name="scheme">The authentication scheme name. Defaults to <see cref="JwtBearerDefaults.AuthenticationScheme"/>.</param>
    /// <returns>The same <paramref name="builder"/> for chaining.</returns>
    public static AuthenticationBuilder AddSecurityJwtBearer(
        this AuthenticationBuilder builder,
        string scheme = JwtBearerDefaults.AuthenticationScheme)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(scheme);

        builder.AddJwtBearer(scheme, options => options.MapInboundClaims = false);

        builder.Services
            .AddOptions<JwtBearerOptions>(scheme)
            .Configure<ITokenHandler>((options, tokenHandler) =>
            {
                if (tokenHandler is not TokenHandler handler)
                {
                    throw new InvalidOperationException(
                        $"{nameof(AddSecurityJwtBearer)} requires the {nameof(ITokenHandler)} registered by AddTokens.");
                }

                options.TokenValidationParameters = handler.ValidationParameters.Clone();
            });

        return builder;
    }
}
