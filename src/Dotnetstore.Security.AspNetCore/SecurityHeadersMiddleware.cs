using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Dotnetstore.Security.AspNetCore;

internal sealed class SecurityHeadersMiddleware(RequestDelegate next, IOptions<SecurityHeadersOptions> options)
{
    private readonly SecurityHeadersOptions _options = options.Value;

    public Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(static state =>
        {
            var (httpContext, headerOptions) = ((HttpContext, SecurityHeadersOptions))state;
            Apply(httpContext, headerOptions);
            return Task.CompletedTask;
        }, (context, _options));

        return next(context);
    }

    private static void Apply(HttpContext context, SecurityHeadersOptions options)
    {
        var headers = context.Response.Headers;

        Set(headers, "X-Content-Type-Options", options.ContentTypeOptions);
        Set(headers, "X-Frame-Options", options.FrameOptions);
        Set(headers, "Referrer-Policy", options.ReferrerPolicy);
        Set(headers, "Content-Security-Policy", options.ContentSecurityPolicy);
        Set(headers, "Permissions-Policy", options.PermissionsPolicy);
        Set(headers, "Cross-Origin-Opener-Policy", options.CrossOriginOpenerPolicy);
        Set(headers, "Cross-Origin-Resource-Policy", options.CrossOriginResourcePolicy);
        Set(headers, "Cache-Control", options.CacheControl);

        if (context.Request.IsHttps)
        {
            Set(headers, "Strict-Transport-Security", options.StrictTransportSecurity);
        }
    }

    private static void Set(IHeaderDictionary headers, string name, string? value)
    {
        if (!string.IsNullOrEmpty(value) && !headers.ContainsKey(name))
        {
            headers[name] = value;
        }
    }
}
